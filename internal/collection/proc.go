package collection

import (
    "fmt"
    "path"
    "os"
    "syscall"
    "strings"
    "path/filepath"
    "strconv"
    "io/ioutil"
)


func getStartTimeFromPidStateFile(pidStatPath string) (uint64, error) {
    procStat, err := ioutil.ReadFile(pidStatPath)
    if err != nil {
        return 0, err
    }
    procStatStr := string(procStat)
    // avoid all sorts of ugly stuff that can happen when comm has unusual characters/spaces
    i := strings.LastIndex(procStatStr, ")")
    if i <= 0 {
        return 0, fmt.Errorf("no comm found in %s: \"%s\"\n", pidStatPath, procStatStr)
    }

    splitStat := strings.SplitN(procStatStr[i+1:], " ", 22)
    if len(splitStat) != 22 {
        return 0, fmt.Errorf("strange result parsing %s: \"%s\"\n", pidStatPath, procStatStr)
    }
    startTimeStr := splitStat[20]
    startTime, err := strconv.ParseUint(startTimeStr, 10, 0)
    if err != nil {
        return 0, fmt.Errorf("failed to parse process start time %s: %w\n", startTimeStr, err)
    }

    return startTime, nil
}

func isMagicSelfProcDir(dirName string) bool {
    return dirName == "self" || dirName == "thread-self"

}

func ScanProcessSocketInodes() (map[uint64]inodeProcessInfo, error) {
    matches, err := filepath.Glob("/proc/*/fd/*")
    if err != nil {
        return nil, fmt.Errorf("failed to scan process fd inodes: %w\n", err)
    }

    inodeProcInfoMap := make(map[uint64]inodeProcessInfo)
    for _, fdPath := range matches {
        var stat syscall.Stat_t
        if err := syscall.Stat(fdPath, &stat); err != nil {
            if !os.IsNotExist(err) {
                return nil, fmt.Errorf("failed to stat file %s: %w\n", fdPath, err)
            }
            continue
        }

        if stat.Mode & syscall.S_IFSOCK != syscall.S_IFSOCK {
            continue
        }

        d, fdStr := path.Split(fdPath)
        procDir := filepath.Dir(filepath.Dir(d))
        _, pidStr := path.Split(procDir)

        if isMagicSelfProcDir(pidStr) {
            continue
        }

        pid, err := strconv.ParseUint(pidStr, 10, 0)
        if err != nil {
            return nil, fmt.Errorf("warning: failed to parse pid %s: %w\n", pidStr, err)
        }
        fd, err := strconv.ParseUint(fdStr, 10, 0)
        if err != nil {
            return nil, fmt.Errorf("failed to parse fd str %s for pid %d: %w\n", fdStr, pid, err)
        }

        startTime, err := getStartTimeFromPidStateFile(filepath.Join(procDir, "stat"))
        if err != nil {
            if !os.IsNotExist(err) {
                return nil, fmt.Errorf("failed to read stat file for pid %d: %w\n", pid, err)
            }
            continue
        }

        existing, ok := inodeProcInfoMap[stat.Ino]
        if !ok || existing.ProcessStartTime > startTime {
            inodeProcInfoMap[stat.Ino] = inodeProcessInfo{Fd: fd, Pid: pid, ProcessStartTime: startTime}
        }
    }
    return inodeProcInfoMap, nil
}

func ScanProcessComms() (map[uint64]string, error) {
    matches, err := filepath.Glob("/proc/*/comm")
    if err != nil {
        return nil, fmt.Errorf("failed to scan process comms: %w\n", err)
    }

    pidCommMap := make(map[uint64]string)
    for _, commPath := range matches {
        comm, err := ioutil.ReadFile(commPath)
        if err != nil {
            if !os.IsNotExist(err) {
                return nil, fmt.Errorf("failed read process comm at %s: %w\n", commPath, err)
            }
            continue
        }

        baseDir := filepath.Dir(commPath)
        _, pidStr := path.Split(baseDir)

        if isMagicSelfProcDir(pidStr) {
            continue
        }

        pid, err := strconv.ParseUint(pidStr, 10, 0)
        if err != nil {
            return nil, fmt.Errorf("warning: failed to parse pid %s: %w\n", pidStr, err)
        }

        pidCommMap[pid] = strings.TrimSpace(string(comm))
    }
    return pidCommMap, nil
}

