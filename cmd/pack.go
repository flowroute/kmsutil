// Copyright © 2016 Flowroute Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"

	"github.com/flowroute/kmsutil/stash"
)

// packCmd represents the pack command
var packCmd = &cobra.Command{
	Use:   "pack <key> <file>",
	Short: "Create a KMS encrypted file",
	Long: `Given an AWS Key Id and a file, produce file.box, containing KMS encrypted
contents of the original file and the appropriate encrypted key to retrieve
it.

The key may be in either the form 'alias/name-here' or
'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

"kmsutil unpack" when run with the appropriate AWS profile credentials will
unpack this file to its original form.

The box file may only be unpacked using credentials from the same AWS region.
`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 2 {
			cmd.Usage()
			os.Exit(1)
		}
		keyId = args[0]
		path = args[1]
		s, err := stash.NewStash(keyId, region)
		if err != nil {
			panic(err)
		}

		plaintext, err := ioutil.ReadFile(path)
		if err != nil {
			fmt.Println(err)
			cmd.Usage()
			os.Exit(1)
		}
		ciphertext, err := s.Encrypt(plaintext)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		outpath := path + ".box"

		err = ioutil.WriteFile(outpath, ciphertext, 0644)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

var (
	keyId string
	path  string
)

func init() {
	RootCmd.AddCommand(packCmd)
}
