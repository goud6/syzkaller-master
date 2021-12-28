// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

// A hint is basically a tuple consisting of a pointer to an argument
// in one of the syscalls of a program and a value, which should be
// assigned to that argument (we call it a replacer).

// A simplified version of hints workflow looks like this:
//		1. Fuzzer launches a program (we call it a hint seed) and collects all
// the comparisons' data for every syscall in the program.
//		2. Next it tries to match the obtained comparison operands' values
// vs. the input arguments' values.
//		3. For every such match the fuzzer mutates the program by
// replacing the pointed argument with the saved value.
//		4. If a valid program is obtained, then fuzzer launches it and
// checks if new coverage is obtained.
// For more insights on particular mutations please see prog/hints_test.go.

/*
    简单解释一下：
    一个hint是一个元组，它由一个指向syscall的一个参数的指针和一个value组成，这个值应当被
赋予到对应的参数上，在syzkaller中被称作一个replacer。
    一个简单的hints的工作流程如下：
    1、Fuzzer启动一个程序(这个程序被称为hint种子)并且收集这个程序中每一个syscall的比较数据。
    2、下一步Fuzzer尝试把获得的比较操作数与输入的参数值进行匹配。
    3、对于每一对匹配成功的值，fuzzer通过替换对应指针保存的值来对程序进行变异。
    4、如果能获得一个有效的程序，然后fuzzer启动程序，检查有没有新的覆盖情况生成。
*/

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

// Example: for comparisons {(op1, op2), (op1, op3), (op1, op4), (op2, op1)}
// this map will store the following:
// m = {
//		op1: {map[op2]: true, map[op3]: true, map[op4]: true},
//		op2: {map[op1]: true}
// }.
type CompMap map[uint64]map[uint64]bool

const (
	maxDataLength = 100
)

var specialIntsSet map[uint64]bool

// 添加新的CompMap,在ipc.go调用
func (m CompMap) AddComp(arg1, arg2 uint64) {
	if _, ok := m[arg1]; !ok {
		m[arg1] = make(map[uint64]bool)
	}
	m[arg1][arg2] = true
}

func (m CompMap) String() string {
	buf := new(bytes.Buffer)
	for v, comps := range m {
		if len(buf.Bytes()) != 0 {
			fmt.Fprintf(buf, ", ")
		}
		fmt.Fprintf(buf, "0x%x:", v)
		for c := range comps {
			fmt.Fprintf(buf, " 0x%x", c)
		}
	}
	return buf.String()
}

// Mutates the program using the comparison operands stored in compMaps.
// For each of the mutants executes the exec callback.
// 变异程序时使用储存在compMaps里面的对比操作数。 对于每一个变异回调参数exec。
//  这个函数主要就调用了一个函数：ForeachArg()。其余出现的execValidate、generateHints()、
// sanitize()都以参数或其他的形式传入，都没有直接调用。
func (p *Prog) MutateWithHints(callIndex int, comps CompMap, exec func(p *Prog)) {
	p = p.Clone()
	c := p.Calls[callIndex]
	//把有害的call转化为无害的call，如果失败了就直接返回。
	//然后进行参数、返回值等等的检查；最后执行程序。
	execValidate := func() {
		// Don't try to fix the candidate program.
		// Assuming the original call was sanitized, we've got a bad call
		// as the result of hint substitution, so just throw it away.
		// 不要尝试去修改condidate 程序，假设源程序 sanitized，我们会得到一个损坏的调用作为hint替换的结果，直接扔掉。
		if p.Target.sanitize(c, false) != nil {
			return
		}
		p.debugValidate()
		exec(p)
	}
	/*
		ForeachArg()又调用了两次foreachArgImpl()。foreachArgImpl()首先执行参数表
		中的函数func(arg Arg, _ *ArgCtx)，在下面的函数中就是执行generateHints。
		然后再根据arg类型的不同做一些不同的处理，再递归调用自身foreachArgImpl()。
		比如，如果类型属于*GroupArg，即结构体或者数组，就先遍历，再进行递归；
		如果arg是*PointerArg，即指针或在虚拟内存空间，就先判断是否为空，如果不为空，赋值再递归；
		如果是*UnionArg，即联合体，就直接进行递归。
	*/
	ForeachArg(c, func(arg Arg, _ *ArgCtx) {
		/*
		   generateHints()用来生成新的hint。主要来判断arg的类型，如果是通过判断的*ConstArg，
		   就调用checkConstArg(a, compMap, exec)；如果是通过判断的*DataArg，就调用
		   checkDataArg(a, compMap, exec)。而这两个函数主要都要调用shrinkExpand()来生成
		   replacer，也就是hints。checkDataArg()比checkConstArg()多的步骤就是需要进行字节序
		   的转换，比较简单。shrinkExpand()是生成hints的核心了，其余部分基本就是为它来判断谁能
		   生成hints，把这个函数单独拿出来在下面讲。
		*/
		generateHints(comps, arg, execValidate)
	})
}

func generateHints(compMap CompMap, arg Arg, exec func()) {
	typ := arg.Type()
	if typ == nil || arg.Dir() == DirOut {
		return
	}
	switch t := typ.(type) {
	case *ProcType:
		// Random proc will not pass validation.
		// We can mutate it, but only if the resulting value is within the legal range.
		return
	case *ConstType:
		if IsPad(typ) {
			return
		}
	case *CsumType:
		// Csum will not pass validation and is always computed.
		return
	case *BufferType:
		switch t.Kind {
		case BufferFilename:
			// This can generate escaping paths and is probably not too useful anyway.
			return
		case BufferString, BufferGlob:
			if len(t.Values) != 0 {
				// These are frequently file names or complete enumerations.
				// Mutating these may be useful iff we intercept strcmp
				// (and filter out file names).
				return
			}
		}
	}

	switch a := arg.(type) {
	case *ConstArg:
		checkConstArg(a, compMap, exec)
	case *DataArg:
		checkDataArg(a, compMap, exec)
	}
}

// 常量替换，直接换掉
func checkConstArg(arg *ConstArg, compMap CompMap, exec func()) {
	original := arg.Val
	// Note: because shrinkExpand returns a map, order of programs is non-deterministic.
	// This can affect test coverage reports.
	// 根据val 和 compMap生成replacer，替换掉val
	for _, replacer := range shrinkExpand(original, compMap, arg.Type().TypeBitSize()) {
		arg.Val = replacer
		exec()
	}
	arg.Val = original
}

// 需要进行字节序的转换
func checkDataArg(arg *DataArg, compMap CompMap, exec func()) {
	bytes := make([]byte, 8)
	data := arg.Data()
	size := len(data)
	if size > maxDataLength {
		size = maxDataLength
	}
	for i := 0; i < size; i++ {
		original := make([]byte, 8)
		copy(original, data[i:])
		val := binary.LittleEndian.Uint64(original)
		for _, replacer := range shrinkExpand(val, compMap, 64) {
			binary.LittleEndian.PutUint64(bytes, replacer)
			copy(data[i:], bytes)
			exec()
		}
		copy(data[i:], original)
	}
}

// Shrink and expand mutations model the cases when the syscall arguments
// are casted to narrower (and wider) integer types.
//
// Motivation for shrink:
// void f(u16 x) {
//		u8 y = (u8)x;
//		if (y == 0xab) {...}
// }
// If we call f(0x1234), then we'll see a comparison 0x34 vs 0xab and we'll
// be unable to match the argument 0x1234 with any of the comparison operands.
// Thus we shrink 0x1234 to 0x34 and try to match 0x34.
// If there's a match for the shrank value, then we replace the corresponding
// bytes of the input (in the given example we'll get 0x12ab).
// Sometimes the other comparison operand will be wider than the shrank value
// (in the example above consider comparison if (y == 0xdeadbeef) {...}).
// In this case we ignore such comparison because we couldn't come up with
// any valid code example that does similar things. To avoid such comparisons
// we check the sizes with leastSize().
//
// Motivation for expand:
// void f(i8 x) {
//		i16 y = (i16)x;
//		if (y == -2) {...}
// }
// Suppose we call f(-1), then we'll see a comparison 0xffff vs 0xfffe and be
// unable to match input vs any operands. Thus we sign extend the input and
// check the extension.
// As with shrink we ignore cases when the other operand is wider.
// Note that executor sign extends all the comparison operands to int64.
func shrinkExpand(v uint64, compMap CompMap, bitsize uint64) []uint64 {
	v = truncateToBitSize(v, bitsize)
	limit := uint64(1<<bitsize - 1) //最大值
	var replacers map[uint64]bool
	for _, iwidth := range []int{8, 4, 2, 1, -4, -2, -1} {
		var width int
		var size, mutant uint64
		if iwidth > 0 {
			//并操作
			width = iwidth
			size = uint64(width) * 8
			mutant = v & ((1 << size) - 1)
		} else {
			// 或操作
			width = -iwidth
			size = uint64(width) * 8
			if size > bitsize {
				size = bitsize
			}
			if v&(1<<(size-1)) == 0 {
				continue
			}
			mutant = v | ^((1 << size) - 1)
		}
		// Use big-endian match/replace for both blobs and ints.
		// Sometimes we have unmarked blobs (no little/big-endian info);
		// for ANYBLOBs we intentionally lose all marking;
		// but even for marked ints we may need this too.
		// Consider that kernel code does not convert the data
		// (i.e. not ntohs(pkt->proto) == ETH_P_BATMAN),
		// but instead converts the constant (i.e. pkt->proto == htons(ETH_P_BATMAN)).
		// In such case we will see dynamic operand that does not match what we have in the program.
		for _, bigendian := range []bool{false, true} {
			if bigendian {
				if width == 1 {
					continue
				}
				mutant = swapInt(mutant, width)
			}
			for newV := range compMap[mutant] {
				// Check the limit for negative numbers.
				if newV > limit && ((^(limit >> 1) & newV) != ^(limit >> 1)) {
					continue
				}
				mask := uint64(1<<size - 1)
				newHi := newV & ^mask
				newV = newV & mask
				if newHi != 0 && newHi^^mask != 0 {
					continue
				}
				if bigendian {
					newV = swapInt(newV, width)
				}
				if specialIntsSet[newV] {
					continue
				}
				// Replace size least significant bits of v with
				// corresponding bits of newV. Leave the rest of v as it was.
				replacer := (v &^ mask) | newV
				if replacer == v {
					continue
				}

				replacer = truncateToBitSize(replacer, bitsize)
				// TODO(dvyukov): should we try replacing with arg+/-1?
				// This could trigger some off-by-ones.
				if replacers == nil {
					replacers = make(map[uint64]bool)
				}
				replacers[replacer] = true
			}
		}
	}
	if replacers == nil {
		return nil
	}
	res := make([]uint64, 0, len(replacers))
	for v := range replacers {
		res = append(res, v)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i] < res[j]
	})
	return res
}

func init() {
	specialIntsSet = make(map[uint64]bool)
	for _, v := range specialInts {
		specialIntsSet[v] = true
	}
}
