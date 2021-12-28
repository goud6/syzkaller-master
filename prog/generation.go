// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
)

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used
// 随机生成ncalls个调用序列.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	// 初始化
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	for len(p.Calls) < ncalls {
		// 通过调用generateCall()来生成calls
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			// 再调用analyze()对call进行分析，对相应的类型做相应的处理。
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	// 对于最后生成的调用，我们可以得到创建资源和溢出nCall的其他调用
	// 删除其中一些调用。最后一次调用中的资源将替换为默认值，这正是我们想要的。
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}
	p.sanitizeFix()
	p.debugValidate()
	return p
}
