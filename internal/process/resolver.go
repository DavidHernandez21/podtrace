package process

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/kubernetes"
)

// ResolvePID builds a PodInfo-like struct for a local process pid by
// reading its cgroup information (works for container and non-container processes).
func ResolvePID(ctx context.Context, pid int) (*kubernetes.PodInfo, error) {
    procPath := config.ProcBasePath
    pidStr := fmt.Sprintf("%d", pid)
    cgroupFile := filepath.Join(procPath, pidStr, "cgroup")
    data, err := os.ReadFile(cgroupFile)
    if err != nil {
        return nil, fmt.Errorf("failed to read cgroup for pid %d: %w", pid, err)
    }
    content := string(data)

    // Try to locate a container id in the cgroup content (long or shortened).
    // We look for common runtime hints and take the last path element as candidate.
    var containerID string
    lines := strings.Split(content, "\n")
    for _, line := range lines {
        if line == "" {
            continue
        }
        // split each cgroup entry into its fields. a typical line is: "10:devices:/docker/abcd..."
        parts := strings.SplitN(line, ":", 3)
        if len(parts) < 3 {
            continue
        }
        cg := strings.TrimSpace(parts[2])
        if cg == "" || cg == "/" {
            continue
        }

        // normalize and split path, handle leading/trailing slashes
        elems := strings.Split(strings.Trim(cg, "/"), "/")
        if len(elems) == 0 {
            continue
        }

        last := elems[len(elems)-1]
        // skip known non-id tokens like slices or kubepods base names
        if last == "kubepods" || strings.HasPrefix(last, "kubepods") || strings.HasSuffix(last, ".slice") || last == "system" || last == "user" {
            // maybe the container id is earlier in the path; search from right to left
            for i := len(elems) - 1; i >= 0; i-- {
                candidate := elems[i]
                if candidate == "" || candidate == "kubepods" || strings.HasSuffix(candidate, ".slice") || candidate == "system" || candidate == "user" {
                    continue
                }
                // crude validation: container id should be alphanumeric and at least 4 chars
                if len(candidate) >= 4 {
                    last = candidate
                    break
                }
            }
        }

        // final sanity check
        if last != "" && looksLikeContainerID(last) {
            containerID = last
            break
        }
    }

    // Derive a cgroup filesystem path from the first "0::" line if available,
    // otherwise pick the third field of the first non-empty line.
    var cgroupPath string
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if strings.HasPrefix(line, "0::") {
            cgroupPath = strings.TrimSpace(strings.TrimPrefix(line, "0::"))
            break
        }
    }
    if cgroupPath == "" {
        for _, line := range lines {
            line = strings.TrimSpace(line)
            if line == "" {
                continue
            }
            parts := strings.SplitN(line, ":", 3)
            if len(parts) >= 3 {
                cgroupPath = strings.TrimSpace(parts[2])
                break
            }
        }
    }

    var fullCgroupPath string
    if cgroupPath == "" || cgroupPath == "/" {
        fullCgroupPath = config.CgroupBasePath
    } else {
        // trim leading slash then join with base so tests can override base path
        fullCgroupPath = filepath.Join(config.CgroupBasePath, strings.Trim(cgroupPath, "/"))
    }

    // Normalize container id value (strip leading slashes)
    containerID = strings.Trim(containerID, "/ ")

    return &kubernetes.PodInfo{
        PodName:       "",
        Namespace:     "",
        ContainerID:   containerID,
        CgroupPath:    fullCgroupPath,
        ContainerName: "",
        Labels:        nil,
        PodIP:         "",
        OwnerKind:     "",
        OwnerName:     "",
    }, nil
}

// looksLikeContainerID attempts to determine whether a path element resembles a container id.
// It handles common wrappers like docker-<id>.scope and checks for a hex-like chunk of sufficient length.
func looksLikeContainerID(s string) bool {
    if s == "" {
        return false
    }
    // strip common suffix
    s = strings.TrimSuffix(s, ".scope")
    // handle common prefixes
    if idx := strings.Index(s, "docker-"); idx == 0 {
        s = s[len("docker-"):]
    }
    if idx := strings.Index(s, "cri-containerd-"); idx == 0 {
        s = s[len("cri-containerd-"):]
    }
    if idx := strings.Index(s, "containerd-"); idx == 0 {
        s = s[len("containerd-"):]
    }

    // collapse non-alphanum to spaces and check tokens
    var b strings.Builder
    for _, r := range s {
        if unicode.IsLetter(r) || unicode.IsDigit(r) {
            b.WriteRune(r)
        } else {
            b.WriteRune(' ')
        }
    }
    tokens := strings.Fields(b.String())
    for _, tok := range tokens {
        if len(tok) < 6 {
            continue
        }
        // count hex characters in token
        hexCount := 0
        for _, r := range tok {
            if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
                hexCount++
            }
        }
        if hexCount >= 6 {
            return true
        }
    }
    return false
}
