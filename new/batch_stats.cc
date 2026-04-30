#include <algorithm>
#include <chrono>
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
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <vector>

using namespace std;
namespace fs = std::filesystem;

struct Job {
    string mode;
    int exponent = 0;
    int repetition = 0;
    int port = 0;
    fs::path rawLogPath;
};

struct RunResult {
    string mode;
    int exponent = 0;
    int datasetSize = 0;
    int repetition = 0;
    int port = 0;
    bool parsed = false;
    bool exitedOk = false;
    int exitCode = -1;
    int intersectionSize = 0;
    bool intersectionOk = false;
    double receiverOfflineTime = 0.0;
    double receiverOnlineTime = 0.0;
    double protocolTotalTime = 0.0;
    double protocolOfflineDataMb = 0.0;
    double protocolOnlineDataMb = 0.0;
    double senderOnlineDataMb = 0.0;
    double receiverOnlineDataMb = 0.0;
    string rawLogPath;
};

struct MetricStats {
    int count = 0;
    double mean = 0.0;
    double min = 0.0;
    double max = 0.0;
    double relativeSpread = numeric_limits<double>::infinity();
};

struct GroupSummary {
    string mode;
    int exponent = 0;
    int totalAttempts = 0;
    int successCount = 0;
    int correctCount = 0;
    bool stable = false;
    bool hitCap = false;

    MetricStats receiverOfflineTime;
    MetricStats receiverOnlineTime;
    MetricStats protocolTotalTime;
    MetricStats protocolOfflineDataMb;
    MetricStats protocolOnlineDataMb;
    MetricStats senderOnlineDataMb;
    MetricStats receiverOnlineDataMb;
};

struct GroupState {
    string mode;
    int exponent = 0;
    int nextRepetition = 1;
    int scheduled = 0;
    bool finished = false;
    vector<RunResult> runs;
};

struct ActiveJob {
    Job job;
    future<RunResult> resultFuture;
};

static string trim(const string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static bool startsWith(const string& s, const string& prefix) {
    return s.rfind(prefix, 0) == 0;
}

static optional<double> parseTrailingDouble(const string& line) {
    istringstream iss(line);
    string token;
    optional<double> last;
    while (iss >> token) {
        try {
            size_t idx = 0;
            double v = stod(token, &idx);
            if (idx == token.size()) last = v;
        } catch (...) {
        }
    }
    return last;
}

static optional<int> parseTrailingInt(const string& line) {
    istringstream iss(line);
    string token;
    optional<int> last;
    while (iss >> token) {
        try {
            size_t idx = 0;
            int v = stoi(token, &idx);
            if (idx == token.size()) last = v;
        } catch (...) {
        }
    }
    return last;
}

static vector<int> parseExponentList(const string& s) {
    vector<int> out;
    string token;
    istringstream iss(s);
    while (getline(iss, token, ',')) {
        token = trim(token);
        if (!token.empty()) out.push_back(stoi(token));
    }
    return out;
}

static string nowTimestamp() {
    auto now = chrono::system_clock::now();
    time_t t = chrono::system_clock::to_time_t(now);
    tm localTm{};
    localtime_r(&t, &localTm);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &localTm);
    return string(buf);
}

static fs::path getExecutableDir() {
    vector<char> buf(4096);
    ssize_t len = readlink("/proc/self/exe", buf.data(), buf.size() - 1);
    if (len <= 0) return fs::current_path();
    buf[len] = '\0';
    return fs::path(buf.data()).parent_path();
}

static RunResult parseRawLog(const fs::path& path, const Job& job, int exitCode) {
    RunResult r;
    r.mode = job.mode;
    r.exponent = job.exponent;
    r.repetition = job.repetition;
    r.port = job.port;
    r.rawLogPath = path.string();
    r.exitCode = exitCode;
    r.exitedOk = (exitCode == 0);

    ifstream in(path);
    if (!in) return r;

    string line;
    bool sawMode = false;
    bool sawDataset = false;
    bool sawOfflineTime = false;
    bool sawOnlineTime = false;
    bool sawTotalTime = false;
    bool sawOfflineMb = false;
    bool sawOnlineMb = false;
    bool sawSenderOnlineMb = false;
    bool sawReceiverOnlineMb = false;

    while (getline(in, line)) {
        string t = trim(line);
        if (startsWith(t, "Mode:")) {
            auto pos = t.find(':');
            r.mode = trim(t.substr(pos + 1));
            sawMode = true;
        } else if (startsWith(t, "Dataset size:")) {
            auto eq = t.find('=');
            if (eq != string::npos) {
                try { r.datasetSize = stoi(trim(t.substr(eq + 1))); sawDataset = true; } catch (...) {}
            }
        } else if (startsWith(t, "Intersection size:")) {
            auto v = parseTrailingInt(t);
            if (v) r.intersectionSize = *v;
        } else if (startsWith(t, "Intersection correct:")) {
            r.intersectionOk = t.find("YES") != string::npos;
        } else if (startsWith(t, "Receiver offline time:")) {
            auto v = parseTrailingDouble(t);
            if (v) { r.receiverOfflineTime = *v; sawOfflineTime = true; }
        } else if (startsWith(t, "Receiver online  time:")) {
            auto v = parseTrailingDouble(t);
            if (v) { r.receiverOnlineTime = *v; sawOnlineTime = true; }
        } else if (startsWith(t, "Protocol total   time:")) {
            auto v = parseTrailingDouble(t);
            if (v) { r.protocolTotalTime = *v; sawTotalTime = true; }
        } else if (startsWith(t, "Protocol offline data:")) {
            auto v = parseTrailingDouble(t);
            if (v) { r.protocolOfflineDataMb = *v; sawOfflineMb = true; }
        } else if (startsWith(t, "Protocol online  data:")) {
            auto v = parseTrailingDouble(t);
            if (v) { r.protocolOnlineDataMb = *v; sawOnlineMb = true; }
        } else if (startsWith(t, "Sender   online  data:")) {
            auto v = parseTrailingDouble(t);
            if (v) { r.senderOnlineDataMb = *v; sawSenderOnlineMb = true; }
        } else if (startsWith(t, "Receiver online  data:")) {
            auto v = parseTrailingDouble(t);
            if (v) { r.receiverOnlineDataMb = *v; sawReceiverOnlineMb = true; }
        }
    }

    r.parsed = sawMode && sawDataset && sawOfflineTime && sawOnlineTime && sawTotalTime &&
               sawOfflineMb && sawOnlineMb && sawSenderOnlineMb && sawReceiverOnlineMb;
    return r;
}

static int runChildToFile(const Job& job, const fs::path& psiExe) {
    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        int fd = ::open(job.rawLogPath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd < 0) _exit(127);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
        execl(psiExe.c_str(), psiExe.c_str(),
              to_string(job.exponent).c_str(),
              job.mode.c_str(),
              to_string(job.port).c_str(),
              (char*)nullptr);
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 128;
}

static MetricStats computeMetricStats(const vector<double>& values) {
    MetricStats s;
    s.count = static_cast<int>(values.size());
    if (values.empty()) return s;
    s.min = *min_element(values.begin(), values.end());
    s.max = *max_element(values.begin(), values.end());
    double sum = 0.0;
    for (double v : values) sum += v;
    s.mean = sum / values.size();
    if (s.mean != 0.0) s.relativeSpread = (s.max - s.min) / s.mean;
    return s;
}

static vector<RunResult> successfulRuns(const GroupState& group) {
    vector<RunResult> out;
    for (const auto& r : group.runs) {
        if (r.exitedOk && r.parsed) out.push_back(r);
    }
    return out;
}

static GroupSummary summarizeGroup(const GroupState& group,
                                   int initialRepetitions,
                                   int maxRepetitions,
                                   double threshold) {
    GroupSummary s;
    s.mode = group.mode;
    s.exponent = group.exponent;
    s.totalAttempts = static_cast<int>(group.runs.size());

    auto okRuns = successfulRuns(group);
    s.successCount = static_cast<int>(okRuns.size());
    for (const auto& r : okRuns) if (r.intersectionOk) s.correctCount += 1;

    vector<double> receiverOfflineTimes;
    vector<double> receiverOnlineTimes;
    vector<double> protocolTotalTimes;
    vector<double> protocolOfflineMbs;
    vector<double> protocolOnlineMbs;
    vector<double> senderOnlineMbs;
    vector<double> receiverOnlineMbs;

    for (const auto& r : okRuns) {
        receiverOfflineTimes.push_back(r.receiverOfflineTime);
        receiverOnlineTimes.push_back(r.receiverOnlineTime);
        protocolTotalTimes.push_back(r.protocolTotalTime);
        protocolOfflineMbs.push_back(r.protocolOfflineDataMb);
        protocolOnlineMbs.push_back(r.protocolOnlineDataMb);
        senderOnlineMbs.push_back(r.senderOnlineDataMb);
        receiverOnlineMbs.push_back(r.receiverOnlineDataMb);
    }

    s.receiverOfflineTime = computeMetricStats(receiverOfflineTimes);
    s.receiverOnlineTime = computeMetricStats(receiverOnlineTimes);
    s.protocolTotalTime = computeMetricStats(protocolTotalTimes);
    s.protocolOfflineDataMb = computeMetricStats(protocolOfflineMbs);
    s.protocolOnlineDataMb = computeMetricStats(protocolOnlineMbs);
    s.senderOnlineDataMb = computeMetricStats(senderOnlineMbs);
    s.receiverOnlineDataMb = computeMetricStats(receiverOnlineMbs);

    bool enoughSamples = s.successCount >= initialRepetitions;
    bool stableTotal = enoughSamples && s.protocolTotalTime.relativeSpread <= threshold;
    s.stable = stableTotal;
    s.hitCap = (group.nextRepetition - 1) >= maxRepetitions && !s.stable;
    return s;
}

static void writeConfig(const fs::path& dir,
                        int initialRepetitions,
                        int maxRepetitions,
                        int jobs,
                        bool detach,
                        double threshold,
                        const vector<int>& exponents,
                        const vector<string>& modes) {
    ofstream out(dir / "config.txt");
    out << "initial_repetitions=" << initialRepetitions << "\n";
    out << "max_repetitions=" << maxRepetitions << "\n";
    out << "jobs=" << jobs << "\n";
    out << "detach=" << (detach ? 1 : 0) << "\n";
    out << "stability_threshold=" << threshold << "\n";
    out << "exponents=";
    for (size_t i = 0; i < exponents.size(); ++i) {
        if (i) out << ",";
        out << exponents[i];
    }
    out << "\nmodes=";
    for (size_t i = 0; i < modes.size(); ++i) {
        if (i) out << ",";
        out << modes[i];
    }
    out << "\n";
}

static void writeResultsCsv(const fs::path& dir, const vector<RunResult>& results) {
    ofstream out(dir / "results.csv");
    out << "mode,exponent,dataset_size,repetition,port,parsed,exit_code,exited_ok,intersection_size,intersection_ok,receiver_offline_time_s,receiver_online_time_s,protocol_total_time_s,protocol_offline_data_mb,protocol_online_data_mb,sender_online_data_mb,receiver_online_data_mb,raw_log\n";
    for (const auto& r : results) {
        out << r.mode << ',' << r.exponent << ',' << r.datasetSize << ',' << r.repetition << ',' << r.port << ','
            << (r.parsed ? 1 : 0) << ',' << r.exitCode << ',' << (r.exitedOk ? 1 : 0) << ','
            << r.intersectionSize << ',' << (r.intersectionOk ? 1 : 0) << ','
            << fixed << setprecision(6)
            << r.receiverOfflineTime << ',' << r.receiverOnlineTime << ',' << r.protocolTotalTime << ','
            << r.protocolOfflineDataMb << ',' << r.protocolOnlineDataMb << ','
            << r.senderOnlineDataMb << ',' << r.receiverOnlineDataMb << ','
            << '"' << r.rawLogPath << '"' << '\n';
    }
}

static void writeAverages(const fs::path& dir, const map<pair<string,int>, GroupSummary>& summaries) {
    ofstream out(dir / "averages.csv");
    out << "mode,exponent,stable,hit_cap,success_count,total_attempts,correct_count,accepted_runs,avg_receiver_offline_time_s,avg_receiver_online_time_s,avg_protocol_total_time_s,avg_protocol_offline_data_mb,avg_protocol_online_data_mb,avg_sender_online_data_mb,avg_receiver_online_data_mb\n";
    for (const auto& [key, s] : summaries) {
        out << s.mode << ',' << s.exponent << ',' << (s.stable ? 1 : 0) << ',' << (s.hitCap ? 1 : 0) << ','
            << s.successCount << ',' << s.totalAttempts << ',' << s.correctCount << ',' << s.successCount << ','
            << fixed << setprecision(6)
            << s.receiverOfflineTime.mean << ',' << s.receiverOnlineTime.mean << ',' << s.protocolTotalTime.mean << ','
            << s.protocolOfflineDataMb.mean << ',' << s.protocolOnlineDataMb.mean << ','
            << s.senderOnlineDataMb.mean << ',' << s.receiverOnlineDataMb.mean << '\n';
    }
}

static void writeStabilityCsv(const fs::path& dir, const map<pair<string,int>, GroupSummary>& summaries) {
    ofstream out(dir / "stability.csv");
    out << "mode,exponent,stable,hit_cap,success_count,total_attempts,offline_mean,offline_min,offline_max,offline_spread,online_mean,online_min,online_max,online_spread,total_mean,total_min,total_max,total_spread\n";
    for (const auto& [key, s] : summaries) {
        out << s.mode << ',' << s.exponent << ',' << (s.stable ? 1 : 0) << ',' << (s.hitCap ? 1 : 0) << ','
            << s.successCount << ',' << s.totalAttempts << ','
            << fixed << setprecision(6)
            << s.receiverOfflineTime.mean << ',' << s.receiverOfflineTime.min << ',' << s.receiverOfflineTime.max << ',' << s.receiverOfflineTime.relativeSpread << ','
            << s.receiverOnlineTime.mean << ',' << s.receiverOnlineTime.min << ',' << s.receiverOnlineTime.max << ',' << s.receiverOnlineTime.relativeSpread << ','
            << s.protocolTotalTime.mean << ',' << s.protocolTotalTime.min << ',' << s.protocolTotalTime.max << ',' << s.protocolTotalTime.relativeSpread << '\n';
    }
}

static void writeSummary(const fs::path& dir, const map<pair<string,int>, GroupSummary>& summaries) {
    ofstream out(dir / "summary.txt");
    out << fixed << setprecision(4);
    out << "Batch statistics summary\n";
    out << "========================================================\n";
    for (const auto& [key, s] : summaries) {
        out << s.mode << " 2^" << s.exponent << "\n";
        out << "  stable/hit_cap:            " << (s.stable ? "YES" : "NO") << "/" << (s.hitCap ? "YES" : "NO") << "\n";
        out << "  success/correct/attempts:  " << s.successCount << "/" << s.correctCount << "/" << s.totalAttempts << "\n";
        out << "  protocol total (control):  mean=" << s.protocolTotalTime.mean << "s  spread=" << (s.protocolTotalTime.relativeSpread * 100.0) << "%\n";
        out << "  receiver offline:          mean=" << s.receiverOfflineTime.mean << "s  spread=" << (s.receiverOfflineTime.relativeSpread * 100.0) << "%\n";
        out << "  receiver online:           mean=" << s.receiverOnlineTime.mean << "s  spread=" << (s.receiverOnlineTime.relativeSpread * 100.0) << "%\n";
        out << "  protocol offline data:     " << s.protocolOfflineDataMb.mean << " MB\n";
        out << "  protocol online data:      " << s.protocolOnlineDataMb.mean << " MB\n";
        out << "  sender online data:        " << s.senderOnlineDataMb.mean << " MB\n";
        out << "  receiver online data:      " << s.receiverOnlineDataMb.mean << " MB\n";
        out << "--------------------------------------------------------\n";
    }
}

static void daemonizeSelf(const fs::path& runLogPath) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    if (pid > 0) {
        cout << "Detached batch runner PID: " << pid << endl;
        exit(0);
    }

    if (setsid() < 0) exit(1);

    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);

    umask(0);
    if (chdir("/") != 0) {
        perror("chdir");
        exit(1);
    }

    int fd = ::open(runLogPath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        int nullFd = ::open("/dev/null", O_RDONLY);
        if (nullFd >= 0) {
            dup2(nullFd, STDIN_FILENO);
            if (nullFd > 2) close(nullFd);
        }
        if (fd > 2) close(fd);
    }
}

static Job makeJob(GroupState& group, int portBase, int seq, const fs::path& rawDir) {
    Job job;
    job.mode = group.mode;
    job.exponent = group.exponent;
    job.repetition = group.nextRepetition++;
    job.port = portBase + seq;
    ostringstream name;
    name << group.mode << "_" << group.exponent << "_rep" << setw(2) << setfill('0') << job.repetition << ".log";
    job.rawLogPath = rawDir / name.str();
    group.scheduled += 1;
    return job;
}

static map<pair<string,int>, GroupSummary> buildSummaries(const vector<GroupState>& groups,
                                                          int initialRepetitions,
                                                          int maxRepetitions,
                                                          double threshold) {
    map<pair<string,int>, GroupSummary> summaries;
    for (const auto& g : groups) {
        summaries[{g.mode, g.exponent}] = summarizeGroup(g, initialRepetitions, maxRepetitions, threshold);
    }
    return summaries;
}

int main(int argc, char** argv) {
    int initialRepetitions = 10;
    int maxRepetitions = 20;
    int jobs = 2;
    bool detach = false;
    double stabilityThreshold = 0.05;
    fs::path baseOutput = fs::current_path() / "stats_runs";
    vector<int> exponents = {16, 18, 20, 22, 24};
    vector<string> modes = {"ot", "vole"};

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if ((arg == "--repetitions" || arg == "--initial-repetitions") && i + 1 < argc) {
            initialRepetitions = stoi(argv[++i]);
        } else if (arg == "--max-repetitions" && i + 1 < argc) {
            maxRepetitions = stoi(argv[++i]);
        } else if (arg == "--jobs" && i + 1 < argc) {
            jobs = stoi(argv[++i]);
        } else if (arg == "--output-dir" && i + 1 < argc) {
            baseOutput = argv[++i];
        } else if (arg == "--exponents" && i + 1 < argc) {
            exponents = parseExponentList(argv[++i]);
        } else if (arg == "--stability-threshold" && i + 1 < argc) {
            stabilityThreshold = stod(argv[++i]);
        } else if (arg == "--detach") {
            detach = true;
        } else {
            cerr << "Usage: ./PSI_batch_stats [--initial-repetitions N|--repetitions N] [--max-repetitions M] [--jobs K] [--output-dir PATH] [--exponents 16,18,...] [--stability-threshold 0.05] [--detach]\n";
            return 1;
        }
    }

    if (maxRepetitions < initialRepetitions) maxRepetitions = initialRepetitions;
    if (jobs < 1) jobs = 1;

    fs::path runDir = baseOutput / nowTimestamp();
    fs::path rawDir = runDir / "raw";
    fs::create_directories(rawDir);
    fs::path runLog = runDir / "run.log";
    fs::path psiExe = getExecutableDir() / "PSI";

    if (detach) {
        cout << "Results directory: " << runDir << endl;
        daemonizeSelf(runLog);
    }

    writeConfig(runDir, initialRepetitions, maxRepetitions, jobs, detach, stabilityThreshold, exponents, modes);

    vector<GroupState> groups;
    for (const auto& mode : modes) {
        for (int exp : exponents) {
            GroupState g;
            g.mode = mode;
            g.exponent = exp;
            groups.push_back(g);
        }
    }

    deque<Job> pending;
    int portBase = 20000;
    int seq = 0;
    for (auto& group : groups) {
        for (int i = 0; i < initialRepetitions; ++i) {
            pending.push_back(makeJob(group, portBase, seq++, rawDir));
        }
    }

    vector<ActiveJob> active;
    vector<RunResult> allResults;

    cout << "Starting batch run with adaptive stability control" << endl;
    cout << "Results directory: " << runDir << endl;
    cout << "Initial repetitions: " << initialRepetitions
         << ", max repetitions: " << maxRepetitions
         << ", jobs: " << jobs
         << ", threshold: " << stabilityThreshold << endl;

    auto persistOutputs = [&]() {
        auto summaries = buildSummaries(groups, initialRepetitions, maxRepetitions, stabilityThreshold);
        writeResultsCsv(runDir, allResults);
        writeAverages(runDir, summaries);
        writeStabilityCsv(runDir, summaries);
        writeSummary(runDir, summaries);
    };

    while (true) {
        while (active.size() < static_cast<size_t>(jobs) && !pending.empty()) {
            Job job = pending.front();
            pending.pop_front();
            ActiveJob aj;
            aj.job = job;
            aj.resultFuture = async(std::launch::async, [job, psiExe]() {
                int exitCode = runChildToFile(job, psiExe);
                return parseRawLog(job.rawLogPath, job, exitCode);
            });
            active.push_back(std::move(aj));
        }

        bool anyGroupUnfinished = false;
        for (const auto& g : groups) {
            if (!g.finished) {
                anyGroupUnfinished = true;
                break;
            }
        }
        if (!anyGroupUnfinished && pending.empty() && active.empty()) break;

        bool progressed = false;
        for (size_t i = 0; i < active.size();) {
            auto status = active[i].resultFuture.wait_for(chrono::milliseconds(50));
            if (status != future_status::ready) {
                ++i;
                continue;
            }

            progressed = true;
            RunResult result = active[i].resultFuture.get();
            allResults.push_back(result);

            for (auto& group : groups) {
                if (group.mode == result.mode && group.exponent == result.exponent) {
                    group.runs.push_back(result);
                    GroupSummary summary = summarizeGroup(group, initialRepetitions, maxRepetitions, stabilityThreshold);
                    int attemptsSoFar = static_cast<int>(group.runs.size());
                    if (!group.finished) {
                        if (summary.stable) {
                            group.finished = true;
                        } else if (attemptsSoFar >= initialRepetitions && group.scheduled < maxRepetitions) {
                            pending.push_back(makeJob(group, portBase, seq++, rawDir));
                        } else if (attemptsSoFar >= group.scheduled && group.scheduled >= maxRepetitions) {
                            group.finished = true;
                        }
                    }
                    break;
                }
            }

            active.erase(active.begin() + i);
            persistOutputs();
        }

        if (!progressed) this_thread::sleep_for(chrono::milliseconds(200));
    }

    persistOutputs();
    cout << "Batch run completed. Results saved to: " << runDir << endl;
    return 0;
}
