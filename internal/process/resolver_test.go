package process

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

    "github.com/gma1k/podtrace/internal/config"
)

func TestResolvePID_CgroupV2(t *testing.T) {
    tmp, err := os.MkdirTemp("", "proc-test-")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmp)

    old := config.ProcBasePath
    config.SetProcBasePath(tmp)
    oldCg := config.CgroupBasePath
    config.SetCgroupBasePath(tmp)
    defer config.SetProcBasePath(old)
    defer config.SetCgroupBasePath(oldCg)

    pid := 42424
    pidDir := filepath.Join(tmp, fmt.Sprintf("%d", pid))
    if err := os.MkdirAll(pidDir, 0755); err != nil {
        t.Fatal(err)
    }

    // simple v2-style cgroup with leading 0:: entry
    cgroupContent := "0::/kubepods/mygroup/abcd12345\n10:cpuset:/kubepods/mygroup/abcd12345\n"
    if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroupContent), 0644); err != nil {
        t.Fatal(err)
    }

    pinfo, err := ResolvePID(context.Background(), pid)
    if err != nil {
        t.Fatalf("ResolvePID failed: %v", err)
    }

    // container id should be the last element
    if pinfo.ContainerID != "abcd12345" {
        t.Fatalf("expected ContainerID abcd12345, got %q", pinfo.ContainerID)
    }

    expectedCgroup := filepath.Join(tmp, "kubepods", "mygroup", "abcd12345")
    if pinfo.CgroupPath != expectedCgroup {
        t.Fatalf("expected CgroupPath %q, got %q", expectedCgroup, pinfo.CgroupPath)
    }

    // In PID mode, ensure Kubernetes fields are not populated
    if pinfo.PodName != "" || pinfo.Namespace != "" || pinfo.ContainerName != "" || pinfo.PodIP != "" || pinfo.OwnerKind != "" || pinfo.OwnerName != "" {
        t.Fatalf("expected Kubernetes fields empty in PID mode, got %+v", pinfo)
    }
}

func TestResolvePID_CgroupV1_Docker(t *testing.T) {
    tmp, err := os.MkdirTemp("", "proc-test-")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmp)

    old := config.ProcBasePath
    config.SetProcBasePath(tmp)
    oldCg := config.CgroupBasePath
    config.SetCgroupBasePath(tmp)
    defer config.SetProcBasePath(old)
    defer config.SetCgroupBasePath(oldCg)

    pid := 52525
    pidDir := filepath.Join(tmp, fmt.Sprintf("%d", pid))
    if err := os.MkdirAll(pidDir, 0755); err != nil {
        t.Fatal(err)
    }

    // v1-like cgroup content referencing docker
    cgroupContent := "10:devices:/docker/fffeedde\n"
    if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroupContent), 0644); err != nil {
        t.Fatal(err)
    }

    pinfo, err := ResolvePID(context.Background(), pid)
    if err != nil {
        t.Fatalf("ResolvePID failed: %v", err)
    }

    if pinfo.ContainerID != "fffeedde" {
        t.Fatalf("expected ContainerID fffeedde, got %q", pinfo.ContainerID)
    }

    expectedCgroup := filepath.Join(tmp, "docker", "fffeedde")
    if pinfo.CgroupPath != expectedCgroup {
        t.Fatalf("expected CgroupPath %q, got %q", expectedCgroup, pinfo.CgroupPath)
    }

    if pinfo.PodName != "" || pinfo.Namespace != "" || pinfo.ContainerName != "" || pinfo.PodIP != "" {
        t.Fatalf("expected Kubernetes fields empty in PID mode, got %+v", pinfo)
    }
}

func TestResolvePID_MissingCgroup(t *testing.T) {
    tmp, err := os.MkdirTemp("", "proc-test-")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmp)

    old := config.ProcBasePath
    config.SetProcBasePath(tmp)
    oldCg := config.CgroupBasePath
    config.SetCgroupBasePath(tmp)
    defer config.SetProcBasePath(old)
    defer config.SetCgroupBasePath(oldCg)

    pid := 12345
    // do not create pid dir or cgroup file

    pinfo, err := ResolvePID(context.Background(), pid)
    if err == nil {
        t.Fatalf("expected error for missing cgroup, got %+v", pinfo)
    }
}

func TestResolvePID_EmptyCgroup(t *testing.T) {
    tmp, err := os.MkdirTemp("", "proc-test-")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmp)

    old := config.ProcBasePath
    config.SetProcBasePath(tmp)
    oldCg := config.CgroupBasePath
    config.SetCgroupBasePath(tmp)
    defer config.SetProcBasePath(old)
    defer config.SetCgroupBasePath(oldCg)

    pid := 33333
    pidDir := filepath.Join(tmp, fmt.Sprintf("%d", pid))
    if err := os.MkdirAll(pidDir, 0755); err != nil {
        t.Fatal(err)
    }
    if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte("\n"), 0644); err != nil {
        t.Fatal(err)
    }

    pinfo, err := ResolvePID(context.Background(), pid)
    if err != nil {
        t.Fatalf("ResolvePID failed for empty cgroup: %v", err)
    }
    // should have empty container id and base cgroup path
    if pinfo.ContainerID != "" {
        t.Fatalf("expected empty ContainerID, got %q", pinfo.ContainerID)
    }
    if pinfo.CgroupPath != tmp {
        t.Fatalf("expected cgroup path %q, got %q", tmp, pinfo.CgroupPath)
    }
}

func TestResolvePID_SystemdSlicePath(t *testing.T) {
    tmp, err := os.MkdirTemp("", "proc-test-")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmp)

    old := config.ProcBasePath
    config.SetProcBasePath(tmp)
    oldCg := config.CgroupBasePath
    config.SetCgroupBasePath(tmp)
    defer config.SetProcBasePath(old)
    defer config.SetCgroupBasePath(oldCg)

    pid := 44444
    pidDir := filepath.Join(tmp, fmt.Sprintf("%d", pid))
    if err := os.MkdirAll(pidDir, 0755); err != nil {
        t.Fatal(err)
    }
    // systemd slice-like path where container id may be earlier
    cgroupContent := "1:name=systemd:/kubepods.slice/kubepods-burstable.slice/docker-abcdef123456.scope\n"
    if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroupContent), 0644); err != nil {
        t.Fatal(err)
    }

    pinfo, err := ResolvePID(context.Background(), pid)
    if err != nil {
        t.Fatalf("ResolvePID failed: %v", err)
    }
    if pinfo.ContainerID != "docker-abcdef123456.scope" && pinfo.ContainerID != "abcdef123456" {
        t.Fatalf("unexpected ContainerID parsed: %q", pinfo.ContainerID)
    }
}

func TestResolvePID_CgroupNoContainerID(t *testing.T) {
    tmp, err := os.MkdirTemp("", "proc-test-")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmp)

    old := config.ProcBasePath
    config.SetProcBasePath(tmp)
    oldCg := config.CgroupBasePath
    config.SetCgroupBasePath(tmp)
    defer config.SetProcBasePath(old)
    defer config.SetCgroupBasePath(oldCg)

    pid := 55555
    pidDir := filepath.Join(tmp, fmt.Sprintf("%d", pid))
    if err := os.MkdirAll(pidDir, 0755); err != nil {
        t.Fatal(err)
    }
    // cgroup path that lacks any container-like id
    cgroupContent := "0::/user.slice/user-1000.slice/session-2.scope\n"
    if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroupContent), 0644); err != nil {
        t.Fatal(err)
    }

    pinfo, err := ResolvePID(context.Background(), pid)
    if err != nil {
        t.Fatalf("ResolvePID failed: %v", err)
    }
    if pinfo.ContainerID != "" {
        t.Fatalf("expected empty ContainerID, got %q", pinfo.ContainerID)
    }
    expected := filepath.Join(tmp, "user.slice", "user-1000.slice", "session-2.scope")
    if pinfo.CgroupPath != expected {
        t.Fatalf("expected CgroupPath %q, got %q", expected, pinfo.CgroupPath)
    }
}
