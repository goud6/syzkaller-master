// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package rpctype contains types of message passed via net/rpc connections
// 包含通过系统各部分之间的net/rpc连接传递的消息类型。
// between various parts of the system.
package rpctype

import (
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/signal"
)

//RPC的输入
type RPCInput struct {
	Call   string        //调用
	Prog   []byte        // prog流
	Signal signal.Serial //一些反馈信号
	Cover  []uint32      //覆盖率数组
}

//候选RPC,包含Prog,以及Minimized 和 Smash 的bool值
type RPCCandidate struct {
	Prog      []byte //Prog流
	Minimized bool
	Smashed   bool
}

//RPCProg 结构体，包含Prog，以及对应的Prog编号和Run编号
type RPCProg struct {
	Prog    []byte
	ProgIdx int
	RunIdx  int
}

//链接参数，连接名，连机机器信息，以及内核模块
type ConnectArgs struct {
	Name        string
	MachineInfo []byte
	Modules     []host.KernelModule
}

type ConnectRes struct {
	EnabledCalls      []int
	GitRevision       string
	TargetRevision    string
	AllSandboxes      bool
	CheckResult       *CheckArgs
	MemoryLeakFrames  []string
	DataRaceFrames    []string
	CoverFilterBitmap []byte
}

//校验参数包括Name，Error, 有效的调用，无效的调用，host的Feature，全局文件路径
type CheckArgs struct {
	Name          string
	Error         string
	EnabledCalls  map[string][]int
	DisabledCalls map[string][]SyscallReason
	Features      *host.Features
	GlobFiles     map[string][]string
}

//调用id 和 无效的Reason
type SyscallReason struct {
	ID     int
	Reason string
}

type NewInputArgs struct {
	Name string
	RPCInput
}

type PollArgs struct {
	Name           string
	NeedCandidates bool
	MaxSignal      signal.Serial
	Stats          map[string]uint64
}

type PollRes struct {
	Candidates []RPCCandidate
	NewInputs  []RPCInput
	MaxSignal  signal.Serial
}

type RunnerConnectArgs struct {
	Pool, VM int
}

type RunnerConnectRes struct {
	// CheckUnsupportedCalls is set to true if the Runner needs to query the kernel
	// for unsupported system calls and report them back to the server.
	CheckUnsupportedCalls bool
}

// UpdateUnsupportedArgs contains the data passed from client to server in an
// UpdateSupported call, namely the system calls not supported by the client's
// kernel.
type UpdateUnsupportedArgs struct {
	// Pool is used to identify the checked kernel.
	Pool int
	// UnsupportedCalls contains the ID's of system calls not supported by the
	// client and the reason for this.
	UnsupportedCalls []SyscallReason
}

// NextExchangeArgs contains the data passed from client to server namely
// identification information of the VM and program execution results.
type NextExchangeArgs struct {
	// Pool/VM are used to identify the instance on which the client is running.
	Pool, VM int
	// ProgIdx is used to uniquely identify the program for which the client is
	// sending results.
	ProgIdx int
	// Hanged is set to true if the program for which we are sending results
	// was killed due to hanging.
	Hanged bool
	// Info contains information about the execution of each system call in the
	// program.
	Info ipc.ProgInfo
	// RunIdx is the number of times this program has been run on the kernel.
	RunIdx int
}

// NextExchaneRes contains the data passed from server to client namely
// programs  to execute on the VM.
type NextExchangeRes struct {
	// RPCProg contains the serialized program that will be sent to the client.
	RPCProg
}

type HubConnectArgs struct {
	// Client/Key are used for authentication.
	Client string
	// The key may be a secret password or the oauth token prefixed by "Bearer ".
	Key string
	// Manager name, must start with Client.
	Manager string
	// See pkg/mgrconfig.Config.HubDomain.
	Domain string
	// Manager has started with an empty corpus and requests whole hub corpus.
	Fresh bool
	// Set of system call names supported by this manager.
	// Used to filter out programs with unsupported calls.
	Calls []string
	// Current manager corpus.
	Corpus [][]byte
}

type HubSyncArgs struct {
	// see HubConnectArgs.
	Client     string
	Key        string
	Manager    string
	NeedRepros bool
	// Programs added to corpus since last sync or connect.
	Add [][]byte
	// Hashes of programs removed from corpus since last sync or connect.
	Del []string
	// Repros found since last sync.
	Repros [][]byte
}

type HubSyncRes struct {
	// Set of inputs from other managers.
	Inputs []HubInput
	// Same as Inputs but for legacy managers that don't understand new format (remove later).
	Progs [][]byte
	// Set of repros from other managers.
	Repros [][]byte
	// Number of remaining pending programs,
	// if >0 manager should do sync again.
	More int
}

type HubInput struct {
	// Domain of the source manager.
	Domain string
	Prog   []byte
}

type RunTestPollReq struct {
	Name string
}

type RunTestPollRes struct {
	ID     int
	Bin    []byte
	Prog   []byte
	Cfg    *ipc.Config
	Opts   *ipc.ExecOpts
	Repeat int
}

type RunTestDoneArgs struct {
	Name   string
	ID     int
	Output []byte
	Info   []*ipc.ProgInfo
	Error  string
}
