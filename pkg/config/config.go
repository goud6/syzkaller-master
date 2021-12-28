// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

//加载配置文件
import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/google/syzkaller/pkg/osutil"
)

//读取文件中的数据
func LoadFile(filename string, cfg interface{}) error {
	if filename == "" {
		return fmt.Errorf("no config file specified")
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}
	return LoadData(data, cfg)
}

//加载数据
func LoadData(data []byte, cfg interface{}) error {
	// Remove comment lines starting with #.
	data = regexp.MustCompile(`(^|\n)\s*#.*?\n`).ReplaceAll(data, nil)
	//解json
	dec := json.NewDecoder(bytes.NewReader(data))
	//当目标为结构且输入包含与目标中任何未忽略的导出字段不匹配的对象键时，将导致解码器返回错误。
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}
	return nil
}

//保存文件
func SaveFile(filename string, cfg interface{}) error {
	data, err := SaveData(cfg)
	if err != nil {
		return err
	}
	return osutil.WriteFile(filename, data)
}

//保存数据
func SaveData(cfg interface{}) ([]byte, error) {
	return json.MarshalIndent(cfg, "", "\t")
}
