package setup

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func newPrompter(in io.Reader, out io.Writer) *prompter {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	r, ok := in.(*bufio.Reader)
	if !ok {
		r = bufio.NewReader(in)
	}
	return &prompter{in: r, out: out}
}

func (p *prompter) askString(label, defaultVal string) (string, error) {
	for {
		if defaultVal != "" {
			fmt.Fprintf(p.out, "%s [%s]: ", label, defaultVal)
		} else {
			fmt.Fprintf(p.out, "%s: ", label)
		}
		line, err := p.readLine()
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			if defaultVal != "" {
				return defaultVal, nil
			}
			fmt.Fprintln(p.out, "  value required")
			continue
		}
		return line, nil
	}
}

func (p *prompter) askYesNo(label string, defaultYes bool) (bool, error) {
	def := "y/N"
	if defaultYes {
		def = "Y/n"
	}
	for {
		fmt.Fprintf(p.out, "%s [%s]: ", label, def)
		line, err := p.readLine()
		if err != nil {
			return false, err
		}
		line = strings.TrimSpace(strings.ToLower(line))
		if line == "" {
			return defaultYes, nil
		}
		switch line {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(p.out, "  enter y or n")
	}
}

func (p *prompter) askChoice(label string, choices []string, defaultIdx int) (string, error) {
	for i, c := range choices {
		mark := " "
		if i == defaultIdx {
			mark = "*"
		}
		fmt.Fprintf(p.out, "  %s %d) %s\n", mark, i+1, c)
	}
	def := strconv.Itoa(defaultIdx + 1)
	for {
		fmt.Fprintf(p.out, "%s [%s]: ", label, def)
		line, err := p.readLine()
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			line = def
		}
		n, err := strconv.Atoi(line)
		if err != nil || n < 1 || n > len(choices) {
			fmt.Fprintf(p.out, "  enter 1-%d\n", len(choices))
			continue
		}
		return choices[n-1], nil
	}
}

func (p *prompter) readLine() (string, error) {
	line, err := p.in.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(line, "\n"), nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func IsInteractive(in *os.File) bool {
	if in == nil {
		in = os.Stdin
	}
	fi, err := in.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
