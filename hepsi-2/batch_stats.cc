#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <vector>

using namespace std;
namespace fs = std::filesystem;

// ============================================================
//  Data structures
// ============================================================

struct Job {
    int recvExponent = 0;
    int sendExponent = 0;
    int repetition = 0;
    int port = 0;
    fs::path rawLogPath;
};

struct RunResult {
    int recvExponent = 0;
    int sendExponent = 0;
    int receiverSize = 0;
    int senderSize = 0;
    int repetition = 0;
    int port = 0;
    bool parsed = false;
    bool exitedOk = false;
    int exitCode = -1;
    int expectedIntersection = 0;
    int intersectionSize = 0;
    bool intersectionOk = false;
    double receiverOfflineSec = 0;
    double receiverOnlineSec = 0;
    double protocolTotalSec = 0;
    double offlineDataMb = 0;
    double onlineDataMb = 0;
    double senderOnlineDataMb = 0;
    double receiverOnlineDataMb = 0;
    string rawLogPath;
};

struct MetricStats {
    int count = 0;
    double mean = 0;
    double min = 0;
    double max = 0;
    double stddev = 0;
    double relativeSpread = numeric_limits<double>::infinity();
};

struct GroupSummary {
    int recvExponent = 0;
    int sendExponent = 0;
    int totalAttempts = 0;
    int successCount = 0;
    int correctCount = 0;
    bool stable = false;
    bool hitCap = false;
    MetricStats receiverOfflineSec;
    MetricStats receiverOnlineSec;
    MetricStats protocolTotalSec;
    MetricStats offlineDataMb;
    MetricStats onlineDataMb;
    MetricStats senderOnlineDataMb;
    MetricStats receiverOnlineDataMb;
};

struct GroupState {
    int recvExponent = 0;
    int sendExponent = 0;
    int nextRepetition = 1;
    int scheduled = 0;
    bool finished = false;
    vector<RunResult> runs;
};

struct ActiveJob {
    Job job;
    future<RunResult> resultFuture;
};

// ============================================================
//  Helpers
// ============================================================

static string trim(const string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == string::npos) return "";
    return s.substr(a, s.find_last_not_of(" \t\r\n") - a + 1);
}

static bool startsWith(const string& s, const string& p) {
    return s.rfind(p, 0) == 0;
}

static optional<double> parseTrailingDouble(const string& line) {
    istringstream iss(line);
    string tok;
    optional<double> last;
    while (iss >> tok) {
        try {
            size_t i;
            double v = stod(tok, &i);
            if (i == tok.size()) last = v;
        } catch (...) {}
    }
    return last;
}

static optional<int> parseTrailingInt(const string& line) {
    istringstream iss(line);
    string tok;
    optional<int> last;
    while (iss >> tok) {
        try {
            size_t i;
            int v = stoi(tok, &i);
            if (i == tok.size()) last = v;
        } catch (...) {}
    }
    return last;
}

static vector<int> parseIntList(const string& s) {
    vector<int> out;
    string tok;
    istringstream iss(s);
    while (getline(iss, tok, ',')) {
        tok = trim(tok);
        if (!tok.empty()) out.push_back(stoi(tok));
    }
    return out;
}

static string nowTimestamp() {
    auto now = chrono::system_clock::now();
    time_t t = chrono::system_clock::to_time_t(now);
    tm lt{};
    localtime_r(&t, &lt);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &lt);
    return buf;
}

static fs::path getExecutableDir() {
    vector<char> buf(4096);
    ssize_t len = readlink("/proc/self/exe", buf.data(), buf.size() - 1);
    if (len <= 0) return fs::current_path();
    buf[len] = '\0';
    return fs::path(buf.data()).parent_path();
}

static void daemonizeSelf(const fs::path& logPath) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    if (pid > 0) {
        cout << "Detached PID: " << pid << endl;
        exit(0);
    }
    if (setsid() < 0) exit(1);
    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    umask(0);
    if (chdir("/") != 0) { /* ignore */ }
    int fd = ::open(logPath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        int nfd = ::open("/dev/null", O_RDONLY);
        if (nfd >= 0) {
            dup2(nfd, STDIN_FILENO);
            if (nfd > 2) close(nfd);
        }
        if (fd > 2) close(fd);
    }
}

// ============================================================
//  Log parsing (matches current PSI output format)
// ============================================================

static RunResult parseRawLog(const fs::path& path, const Job& job, int exitCode) {
    RunResult r;
    r.recvExponent = job.recvExponent;
    r.sendExponent = job.sendExponent;
    r.receiverSize = 1 << job.recvExponent;
    r.senderSize = 1 << job.sendExponent;
    r.repetition = job.repetition;
    r.port = job.port;
    r.rawLogPath = path.string();
    r.exitCode = exitCode;
    r.exitedOk = (exitCode == 0);

    ifstream in(path);
    if (!in) return r;

    string line;
    int sawCount = 0;
    while (getline(in, line)) {
        string t = trim(line);
        if (startsWith(t, "Expected intersection:")) {
            auto v = parseTrailingInt(t);
            if (v) {
                r.expectedIntersection = *v;
                sawCount++;
            }
        } else if (startsWith(t, "Intersection size:")) {
            auto v = parseTrailingInt(t);
            if (v) {
                r.intersectionSize = *v;
                sawCount++;
            }
        } else if (startsWith(t, "Intersection correct:")) {
            r.intersectionOk = (t.find("YES") != string::npos);
            sawCount++;
        } else if (startsWith(t, "Receiver offline time:")) {
            auto v = parseTrailingDouble(t);
            if (v) {
                r.receiverOfflineSec = *v;
                sawCount++;
            }
        } else if (startsWith(t, "Receiver online  time:")) {
            auto v = parseTrailingDouble(t);
            if (v) {
                r.receiverOnlineSec = *v;
                sawCount++;
            }
        } else if (startsWith(t, "Protocol total   time:")) {
            auto v = parseTrailingDouble(t);
            if (v) {
                r.protocolTotalSec = *v;
                sawCount++;
            }
        } else if (startsWith(t, "Protocol offline data:")) {
            auto v = parseTrailingDouble(t);
            if (v) {
                r.offlineDataMb = *v;
                sawCount++;
            }
        } else if (startsWith(t, "Protocol online  data:")) {
            auto v = parseTrailingDouble(t);
            if (v) {
                r.onlineDataMb = *v;
                sawCount++;
            }
        } else if (startsWith(t, "Sender   online  data:")) {
            auto v = parseTrailingDouble(t);
            if (v) {
                r.senderOnlineDataMb = *v;
                sawCount++;
            }
        } else if (startsWith(t, "Receiver online  data:")) {
            auto v = parseTrailingDouble(t);
            if (v) {
                r.receiverOnlineDataMb = *v;
                sawCount++;
            }
        }
    }

    r.parsed = (sawCount >= 10);
    return r;
}

// ============================================================
//  Child process execution
// ============================================================

static int runChildToFile(const Job& job, const fs::path& exe) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int fd = ::open(job.rawLogPath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd < 0) _exit(127);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
        execl(exe.c_str(), exe.c_str(),
              to_string(job.recvExponent).c_str(),
              to_string(job.sendExponent).c_str(),
              "0",
              to_string(job.port).c_str(),
              (char*)nullptr);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}

// ============================================================
//  Statistics
// ============================================================

static MetricStats computeStats(const vector<double>& v) {
    MetricStats s;
    s.count = static_cast<int>(v.size());
    if (v.empty()) return s;
    s.min = *min_element(v.begin(), v.end());
    s.max = *max_element(v.begin(), v.end());
    double sum = 0;
    for (double x : v) sum += x;
    s.mean = sum / v.size();
    double var = 0;
    for (double x : v) var += (x - s.mean) * (x - s.mean);
    s.stddev = v.size() > 1 ? sqrt(var / (v.size() - 1)) : 0;
    if (s.mean != 0) s.relativeSpread = (s.max - s.min) / s.mean;
    return s;
}

static GroupSummary summarizeGroup(const GroupState& g, int initReps, int maxReps, double threshold) {
    GroupSummary s;
    s.recvExponent = g.recvExponent;
    s.sendExponent = g.sendExponent;
    s.totalAttempts = static_cast<int>(g.runs.size());

    vector<double> offSec, onSec, totalSec, offMb, onMb, sOnMb, rOnMb;
    for (auto& r : g.runs) {
        if (!r.exitedOk || !r.parsed) continue;
        s.successCount++;
        if (r.intersectionOk) s.correctCount++;
        offSec.push_back(r.receiverOfflineSec);
        onSec.push_back(r.receiverOnlineSec);
        totalSec.push_back(r.protocolTotalSec);
        offMb.push_back(r.offlineDataMb);
        onMb.push_back(r.onlineDataMb);
        sOnMb.push_back(r.senderOnlineDataMb);
        rOnMb.push_back(r.receiverOnlineDataMb);
    }

    s.receiverOfflineSec = computeStats(offSec);
    s.receiverOnlineSec = computeStats(onSec);
    s.protocolTotalSec = computeStats(totalSec);
    s.offlineDataMb = computeStats(offMb);
    s.onlineDataMb = computeStats(onMb);
    s.senderOnlineDataMb = computeStats(sOnMb);
    s.receiverOnlineDataMb = computeStats(rOnMb);

    s.stable = s.successCount >= initReps && s.receiverOnlineSec.relativeSpread <= threshold;
    s.hitCap = (g.nextRepetition - 1) >= maxReps && !s.stable;
    return s;
}

// ============================================================
//  Job scheduling
// ============================================================

static Job makeJob(GroupState& g, int portBase, int& seq, const fs::path& rawDir) {
    Job j;
    j.recvExponent = g.recvExponent;
    j.sendExponent = g.sendExponent;
    j.repetition = g.nextRepetition++;
    j.port = portBase + seq++;
    ostringstream n;
    n << "r" << j.recvExponent << "_s" << j.sendExponent
      << "_rep" << setw(2) << setfill('0') << j.repetition << ".log";
    j.rawLogPath = rawDir / n.str();
    g.scheduled++;
    return j;
}

// ============================================================
//  Output writers
// ============================================================

static void writeConfig(const fs::path& dir, int initReps, int maxReps, int jobs, bool detach,
                        double threshold, const vector<int>& recv, const vector<int>& send) {
    ofstream o(dir / "config.txt");
    o << "initial_repetitions=" << initReps
      << "\nmax_repetitions=" << maxReps
      << "\njobs=" << jobs
      << "\ndetach=" << (detach ? 1 : 0)
      << "\nstability_threshold=" << threshold
      << "\nrecv_exponents=";
    for (size_t i = 0; i < recv.size(); ++i) {
        if (i) o << ',';
        o << recv[i];
    }
    o << "\nsend_exponents=";
    for (size_t i = 0; i < send.size(); ++i) {
        if (i) o << ',';
        o << send[i];
    }
    o << "\nblock_size_mode=PSI auto default (recvLog>=20 -> 7680, else 6144)\n";
}

static void writeResultsCsv(const fs::path& dir, const vector<RunResult>& results) {
    ofstream o(dir / "results.csv");
    o << "recv_exp,send_exp,recv_n,send_n,rep,port,parsed,exit,ok,expected_isect,isect,correct,"
      << "receiver_offline_s,receiver_online_s,protocol_total_s,offline_mb,online_mb,"
      << "sender_online_mb,receiver_online_mb,log\n";
    for (auto& r : results) {
        o << r.recvExponent << ',' << r.sendExponent << ','
          << r.receiverSize << ',' << r.senderSize << ','
          << r.repetition << ',' << r.port << ','
          << r.parsed << ',' << r.exitCode << ',' << r.exitedOk << ','
          << r.expectedIntersection << ',' << r.intersectionSize << ',' << r.intersectionOk << ','
          << fixed << setprecision(4)
          << r.receiverOfflineSec << ',' << r.receiverOnlineSec << ',' << r.protocolTotalSec << ','
          << r.offlineDataMb << ',' << r.onlineDataMb << ','
          << r.senderOnlineDataMb << ',' << r.receiverOnlineDataMb << ','
          << '"' << r.rawLogPath << "\"\n";
    }
}

static void writeAverages(const fs::path& dir, const map<pair<int,int>, GroupSummary>& sums) {
    ofstream o(dir / "averages.csv");
    o << "recv_exp,send_exp,stable,hit_cap,success,attempts,correct,"
      << "avg_receiver_offline_s,stddev_receiver_offline_s,"
      << "avg_receiver_online_s,stddev_receiver_online_s,"
      << "avg_protocol_total_s,stddev_protocol_total_s,"
      << "avg_offline_mb,avg_online_mb,avg_sender_online_mb,avg_receiver_online_mb\n";
    for (auto& [k, s] : sums) {
        o << s.recvExponent << ',' << s.sendExponent << ','
          << s.stable << ',' << s.hitCap << ','
          << s.successCount << ',' << s.totalAttempts << ',' << s.correctCount << ','
          << fixed << setprecision(4)
          << s.receiverOfflineSec.mean << ',' << s.receiverOfflineSec.stddev << ','
          << s.receiverOnlineSec.mean << ',' << s.receiverOnlineSec.stddev << ','
          << s.protocolTotalSec.mean << ',' << s.protocolTotalSec.stddev << ','
          << s.offlineDataMb.mean << ',' << s.onlineDataMb.mean << ','
          << s.senderOnlineDataMb.mean << ',' << s.receiverOnlineDataMb.mean << '\n';
    }
}

static void writeSummary(const fs::path& dir, const map<pair<int,int>, GroupSummary>& sums) {
    ofstream o(dir / "summary.txt");
    o << fixed << setprecision(2);
    o << "HE-PSI batch statistics summary\n";
    o << "================================================================\n";
    o << "Block size mode: inherit PSI automatic default (recvLog>=20 -> 7680, else 6144)\n";
    o << "================================================================\n";
    for (auto& [k, s] : sums) {
        o << "recv=2^" << s.recvExponent << "  send=2^" << s.sendExponent << "\n";
        o << "  runs: " << s.successCount << "/" << s.totalAttempts
          << "  correct: " << s.correctCount
          << "  stable: " << (s.stable ? "YES" : "NO")
          << (s.hitCap ? " (hit cap)" : "") << "\n";
        o << "  receiver offline: mean=" << s.receiverOfflineSec.mean
          << " s  stddev=" << s.receiverOfflineSec.stddev << " s\n";
        o << "  receiver online : mean=" << s.receiverOnlineSec.mean
          << " s  stddev=" << s.receiverOnlineSec.stddev
          << " s  spread=" << (s.receiverOnlineSec.relativeSpread * 100.0) << "%\n";
        o << "  total time      : mean=" << s.protocolTotalSec.mean
          << " s  stddev=" << s.protocolTotalSec.stddev << " s\n";
        o << "  online data     : " << s.onlineDataMb.mean << " MB"
          << "  (Sender " << s.senderOnlineDataMb.mean
          << " MB + Receiver " << s.receiverOnlineDataMb.mean << " MB)\n";
        o << "  offline data    : " << s.offlineDataMb.mean << " MB\n";
        o << "----------------------------------------------------------------\n";
    }
}

int main(int argc, char** argv) {
    int initReps = 10;
    int maxReps = 20;
    int jobs = 2;
    bool detach = false;
    double threshold = 0.08;
    fs::path baseOutput = fs::current_path() / "stats_runs";
    vector<int> recvExponents = {20, 22, 24};
    vector<int> sendExponents = {0, 6, 8, 10};

    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        if ((a == "--repetitions" || a == "--initial-repetitions") && i + 1 < argc) initReps = stoi(argv[++i]);
        else if (a == "--max-repetitions" && i + 1 < argc) maxReps = stoi(argv[++i]);
        else if (a == "--jobs" && i + 1 < argc) jobs = stoi(argv[++i]);
        else if (a == "--output-dir" && i + 1 < argc) baseOutput = argv[++i];
        else if (a == "--recv-exponents" && i + 1 < argc) recvExponents = parseIntList(argv[++i]);
        else if (a == "--send-exponents" && i + 1 < argc) sendExponents = parseIntList(argv[++i]);
        else if (a == "--stability-threshold" && i + 1 < argc) threshold = stod(argv[++i]);
        else if (a == "--detach") detach = true;
        else {
            cerr << "Usage: ./PSI_batch_stats [--repetitions N] [--max-repetitions M] [--jobs K] "
                    "[--output-dir PATH] [--recv-exponents 20,22,24] [--send-exponents 0,6,8,10] "
                    "[--stability-threshold 0.08] [--detach]\n";
            return 1;
        }
    }
    if (maxReps < initReps) maxReps = initReps;
    if (jobs < 1) jobs = 1;

    fs::path runDir = baseOutput / nowTimestamp();
    fs::path rawDir = runDir / "raw";
    fs::create_directories(rawDir);
    fs::path runLog = runDir / "run.log";
    fs::path exe = getExecutableDir() / "PSI";

    if (detach) {
        cout << "Results: " << runDir << endl;
        daemonizeSelf(runLog);
    }

    writeConfig(runDir, initReps, maxReps, jobs, detach, threshold, recvExponents, sendExponents);

    vector<GroupState> groups;
    for (int r : recvExponents)
        for (int s : sendExponents)
            groups.push_back(GroupState{r, s});

    deque<Job> pending;
    int portBase = 20000;
    int seq = 0;
    for (auto& g : groups)
        for (int i = 0; i < initReps; ++i)
            pending.push_back(makeJob(g, portBase, seq, rawDir));

    vector<ActiveJob> active;
    vector<RunResult> allResults;

    size_t totalGroups = groups.size();
    size_t totalInitJobs = totalGroups * initReps;
    cout << "Starting batch run: " << totalGroups << " groups × " << initReps
         << " reps = " << totalInitJobs << " initial jobs (max " << maxReps << " per group)" << endl;
    cout << "Results: " << runDir << endl;

    auto persistAll = [&]() {
        map<pair<int,int>, GroupSummary> sums;
        for (auto& g : groups)
            sums[{g.recvExponent, g.sendExponent}] = summarizeGroup(g, initReps, maxReps, threshold);
        writeResultsCsv(runDir, allResults);
        writeAverages(runDir, sums);
        writeSummary(runDir, sums);
    };

    while (true) {
        while (static_cast<int>(active.size()) < jobs && !pending.empty()) {
            Job j = pending.front();
            pending.pop_front();
            ActiveJob aj;
            aj.job = j;
            aj.resultFuture = async(launch::async, [j, exe]() {
                int ec = runChildToFile(j, exe);
                return parseRawLog(j.rawLogPath, j, ec);
            });
            active.push_back(move(aj));
        }

        bool anyUnfinished = false;
        for (auto& g : groups) {
            if (!g.finished) {
                anyUnfinished = true;
                break;
            }
        }
        if (!anyUnfinished && pending.empty() && active.empty()) break;

        bool progressed = false;
        for (size_t i = 0; i < active.size();) {
            if (active[i].resultFuture.wait_for(chrono::milliseconds(50)) != future_status::ready) {
                ++i;
                continue;
            }
            progressed = true;
            RunResult result = active[i].resultFuture.get();
            allResults.push_back(result);

            for (auto& g : groups) {
                if (g.recvExponent != result.recvExponent || g.sendExponent != result.sendExponent) continue;
                g.runs.push_back(result);
                auto summary = summarizeGroup(g, initReps, maxReps, threshold);
                if (!g.finished) {
                    if (summary.stable) {
                        g.finished = true;
                    } else if (static_cast<int>(g.runs.size()) >= initReps && g.scheduled < maxReps) {
                        pending.push_back(makeJob(g, portBase, seq, rawDir));
                    } else if (static_cast<int>(g.runs.size()) >= g.scheduled && g.scheduled >= maxReps) {
                        g.finished = true;
                    }
                }
                break;
            }

            active.erase(active.begin() + i);
            persistAll();
        }
        if (!progressed) this_thread::sleep_for(chrono::milliseconds(200));
    }

    persistAll();
    cout << "Batch run completed. Results: " << runDir << endl;
    return 0;
}
