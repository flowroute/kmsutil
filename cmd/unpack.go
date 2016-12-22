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
	"strings"

	"github.com/flowroute/kmsutil/stash"
	"github.com/spf13/cobra"
)

// unpackCmd represents the unpack command
var unpackCmd = &cobra.Command{
	Use:   "unpack <file.box>",
	Short: "Decrypt a prepared file to original contents",
	Long: `Given a KMS encrypted box file, decrypt it to reproduce the original file.

This will overwrite any copy of the original file already in place with the
version that was packed into the box file.

The decryption must use the same region as the box was packed for, and 
profile must have the appropriate IAM rights to use the KMS key.
`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			cmd.Usage()
			os.Exit(1)
		}
		path = args[0]

		// Don't need a KeyID to decrypt (it's in the file).
		s, err := stash.NewStash("", region, profile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		ciphertext, err := ioutil.ReadFile(path)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		plaintext, err := s.Decrypt(ciphertext)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		outpath := strings.TrimSuffix(path, ".box")

		err = ioutil.WriteFile(outpath, plaintext, 0644)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(unpackCmd)
}
