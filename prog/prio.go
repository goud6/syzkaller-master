// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"sort"
)

// Calulation of call-to-call priorities.
// For a given pair of calls X and Y, the priority is our guess as to whether
// additional of call Y into a program containing call X is likely to give
// new coverage or not.
// The current algorithm has two components: static and dynamic.
// The static component is based on analysis of argument types. For example,
// if call X and call Y both accept fd[sock], then they are more likely to give
// new coverage together.
// The dynamic component is based on frequency of occurrence of a particular
// pair of syscalls in a single program in corpus. For example, if socket and
// connect frequently occur in programs together, we give higher priority to
// this pair of syscalls.
// Note: the current implementation is very basic, there is no theory behind any
// constants.

//没有理论支撑，很基础的实现，因此这里也是改进较多的点
func (target *Target) CalculatePriorities(corpus []*Prog) [][]int32 {
	//静态
	static := target.calcStaticPriorities()
	if len(corpus) != 0 {
		//动态
		dynamic := target.calcDynamicPrio(corpus)
		for i, prios := range dynamic {
			dst := static[i]
			for j, p := range prios {
				dst[j] = dst[j] * p / prioHigh
			}
		}
	}
	return static
}

func (target *Target) calcStaticPriorities() [][]int32 {
	uses := target.calcResourceUsage() //获得调用的资源使用表map[string]map[int]weights
	//创建二维关系表
	prios := make([][]int32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]int32, len(target.Syscalls))
	}
	//遍历use
	for _, weights := range uses {
		for _, w0 := range weights {
			for _, w1 := range weights {
				if w0.call == w1.call {
					// Self-priority is assigned below.
					continue
				}
				// The static priority is assigned based on the direction of arguments. A higher priority will be
				// assigned when c0 is a call that produces a resource and c1 a call that uses that resource.
				// 设置了资源的赋值方向，read 或 weight
				prios[w0.call][w1.call] += w0.inout*w1.in*3/2 + w0.inout*w1.inout
			}
		}
	}
	normalizePrio(prios)
	// The value assigned for self-priority (call wrt itself) have to be high, but not too high.
	// 把自相关设置的高一点，但不要太高
	for c0, pp := range prios {
		pp[c0] = prioHigh * 9 / 10
	}
	return prios
}

func (target *Target) calcResourceUsage() map[string]map[int]weights {
	uses := make(map[string]map[int]weights) //key是string,代表一种资源，value 是一个map,call id to weights
	ForeachType(target.Syscalls, func(t Type, ctx TypeCtx) {
		c := ctx.Meta
		// noteUsage中，同一种资源同一个系统调用只会记录一个最大值
		switch a := t.(type) {
		case *ResourceType:
			if target.AuxResources[a.Desc.Name] {
				noteUsage(uses, c, 1, ctx.Dir, "res%v", a.Desc.Name)
			} else {
				str := "res"
				for i, k := range a.Desc.Kind {
					str += "-" + k
					w := int32(10)
					if i < len(a.Desc.Kind)-1 {
						w = 2
					}
					noteUsage(uses, c, w, ctx.Dir, str)
				}
			}
		case *PtrType:
			if _, ok := a.Elem.(*StructType); ok {
				noteUsage(uses, c, 10, ctx.Dir, "ptrto-%v", a.Elem.Name())
			}
			if _, ok := a.Elem.(*UnionType); ok {
				noteUsage(uses, c, 10, ctx.Dir, "ptrto-%v", a.Elem.Name())
			}
			if arr, ok := a.Elem.(*ArrayType); ok {
				noteUsage(uses, c, 10, ctx.Dir, "ptrto-%v", arr.Elem.Name())
			}
		case *BufferType:
			switch a.Kind {
			case BufferBlobRand, BufferBlobRange, BufferText:
			case BufferString, BufferGlob:
				if a.SubKind != "" {
					noteUsage(uses, c, 2, ctx.Dir, fmt.Sprintf("str-%v", a.SubKind))
				}
			case BufferFilename:
				noteUsage(uses, c, 10, DirIn, "filename")
			default:
				panic("unknown buffer kind")
			}
		case *VmaType:
			noteUsage(uses, c, 5, ctx.Dir, "vma")
		case *IntType:
			switch a.Kind {
			case IntPlain, IntRange:
			default:
				panic("unknown int kind")
			}
		}
	})
	return uses
}

type weights struct {
	call  int
	in    int32
	inout int32
}

func noteUsage(uses map[string]map[int]weights, c *Syscall, weight int32, dir Dir, str string, args ...interface{}) {
	id := fmt.Sprintf(str, args...)
	if uses[id] == nil {
		uses[id] = make(map[int]weights)
	}
	callWeight := uses[id][c.ID] //找到c.ID的权重
	callWeight.call = c.ID       //权重中嵌套了系统调用的ID
	if dir != DirOut {
		if weight > uses[id][c.ID].in {
			callWeight.in = weight
		}
	}
	if weight > uses[id][c.ID].inout {
		callWeight.inout = weight
	}
	uses[id][c.ID] = callWeight
}

func (target *Target) calcDynamicPrio(corpus []*Prog) [][]int32 {
	prios := make([][]int32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]int32, len(target.Syscalls))
	}
	for _, p := range corpus {
		for idx0, c0 := range p.Calls {
			// 只要c1在c0的后面，权重就加1
			for _, c1 := range p.Calls[idx0+1:] {
				prios[c0.Meta.ID][c1.Meta.ID]++
			}
		}
	}
	normalizePrio(prios)
	return prios
}

const (
	prioLow  = 10
	prioHigh = 1000
)

// normalizePrio normalizes priorities to [prioLow..prioHigh] range.
func normalizePrio(prios [][]int32) {
	for _, prio := range prios {
		max := int32(1)
		for _, p := range prio {
			if max < p {
				max = p
			}
		}
		for i, p := range prio {
			prio[i] = prioLow + p*(prioHigh-prioLow)/max
		}
	}
}

// ChooseTable allows to do a weighted choice of a syscall for a given syscall
// based on call-to-call priorities and a set of enabled syscalls.
type ChoiceTable struct {
	target *Target
	runs   [][]int32
	calls  []*Syscall
}

func (target *Target) BuildChoiceTable(corpus []*Prog, enabled map[*Syscall]bool) *ChoiceTable {
	// enabled就是在架构中可以使用的syscall
	//如果enabled == nil，把target.Syscalls依次赋值给enabled，并置为true
	if enabled == nil {
		enabled = make(map[*Syscall]bool)
		for _, c := range target.Syscalls {
			enabled[c] = true
		}
	}
	//删除不可用的
	for call := range enabled {
		if call.Attrs.Disabled {
			delete(enabled, call)
		}
	}
	var enabledCalls []*Syscall
	for c := range enabled {
		enabledCalls = append(enabledCalls, c)
	}
	//加入到enabledCalls中
	if len(enabledCalls) == 0 {
		panic("no syscalls enabled")
	}
	// 按照ID大小及逆行排序
	sort.Slice(enabledCalls, func(i, j int) bool {
		return enabledCalls[i].ID < enabledCalls[j].ID
	})
	//对corpus进行检查，查看是否有不可用的syscall
	for _, p := range corpus {
		for _, call := range p.Calls {
			if !enabled[call.Meta] {
				fmt.Printf("corpus contains disabled syscall %v\n", call.Meta.Name)
				panic("disabled syscall")
			}
		}
	}
	//计算prios,并保存到fuzzer.choiceTable
	prios := target.CalculatePriorities(corpus)
	run := make([][]int32, len(target.Syscalls))
	for i := range run {
		if !enabled[target.Syscalls[i]] {
			continue
		}
		run[i] = make([]int32, len(target.Syscalls))
		var sum int32
		for j := range run[i] {
			if enabled[target.Syscalls[j]] {
				sum += prios[i][j]
			}
			run[i][j] = sum
		}
	}
	return &ChoiceTable{target, run, enabledCalls}
}

func (ct *ChoiceTable) Enabled(call int) bool {
	return ct.runs[call] != nil
}

func (ct *ChoiceTable) choose(r *rand.Rand, bias int) int {
	if bias < 0 {
		bias = ct.calls[r.Intn(len(ct.calls))].ID //最大值
	}
	if !ct.Enabled(bias) {
		fmt.Printf("bias to disabled syscall %v\n", ct.target.Syscalls[bias].Name)
		panic("disabled syscall")
	}
	// 二分找到第一个满足的
	run := ct.runs[bias]
	x := int32(r.Intn(int(run[len(run)-1])) + 1)
	res := sort.Search(len(run), func(i int) bool {
		return run[i] >= x
	})
	if !ct.Enabled(res) {
		panic("selected disabled syscall")
	}
	return res
}
