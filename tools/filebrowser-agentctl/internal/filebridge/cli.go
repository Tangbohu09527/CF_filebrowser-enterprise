package filebridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const maxInputBytes = 1 << 20

type CLIOptions struct {
	ConfigFile         string
	InputFile          string
	Command            string
	Apply              bool
	TokenFromStdin     bool
	AllowLocalhostHTTP bool
	Help               bool
}

var supportedCommands = map[string]struct{}{
	"ping": {}, "whoami": {}, "capabilities": {}, "sources": {}, "list": {}, "search": {},
	"stat": {}, "checksum": {}, "read": {}, "download": {}, "mkdir": {}, "upload-new": {},
}

var prohibitedCommands = map[string]struct{}{
	"delete": {}, "share": {}, "token": {}, "tokens": {}, "user": {}, "users": {}, "acl": {},
	"http": {}, "request": {}, "shell": {}, "exec": {}, "move": {}, "rename": {}, "overwrite": {},
}

func RunCLI(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	options, err := parseCLI(args)
	if err != nil {
		writeResponse(stdout, startupError("", err))
		return 2
	}
	if options.Help {
		writeResponse(stdout, helpResponse())
		return 0
	}
	if _, prohibited := prohibitedCommands[options.Command]; prohibited {
		writeResponse(stdout, startupError(options.Command, bridgeError("dangerous_command", "command is intentionally prohibited")))
		return 2
	}
	if _, supported := supportedCommands[options.Command]; !supported {
		writeResponse(stdout, startupError(options.Command, bridgeError("unsupported_command", "command is not supported")))
		return 2
	}
	if options.Apply && !isWriteCommand(options.Command) {
		writeResponse(stdout, startupError(options.Command, bridgeError("invalid_cli", "--apply is valid only for mkdir and upload-new")))
		return 2
	}

	config, err := LoadConfig(options.ConfigFile, options.AllowLocalhostHTTP)
	if err != nil {
		writeResponse(stdout, startupError(options.Command, err))
		return 2
	}
	bufferedStdin := bufio.NewReader(stdin)
	token, err := LoadToken(config, options.TokenFromStdin, bufferedStdin)
	if err != nil {
		writeResponse(stdout, startupError(options.Command, err))
		return 2
	}
	input, err := readInput(options.InputFile, bufferedStdin)
	if err != nil {
		writeResponse(stdout, startupError(options.Command, err))
		return 2
	}
	audit, err := NewAuditLogger(config, stderr)
	if err != nil {
		writeResponse(stdout, startupError(options.Command, err))
		return 2
	}
	defer audit.Close()
	runner := NewRunner(config, NewClient(config, token), audit)
	response := runner.Run(ctx, options.Command, input, options.Apply)
	writeResponse(stdout, response)
	if !response.OK {
		return 1
	}
	return 0
}

func parseCLI(args []string) (CLIOptions, error) {
	options := CLIOptions{InputFile: "-"}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--help" || argument == "-h":
			options.Help = true
		case argument == "--apply":
			options.Apply = true
		case argument == "--token-stdin":
			options.TokenFromStdin = true
		case argument == "--allow-localhost-http":
			options.AllowLocalhostHTTP = true
		case argument == "--config" || argument == "--input":
			if index+1 >= len(args) {
				return CLIOptions{}, bridgeError("invalid_cli", argument+" requires a value")
			}
			index++
			if argument == "--config" {
				options.ConfigFile = args[index]
			} else {
				options.InputFile = args[index]
			}
		case strings.HasPrefix(argument, "--config="):
			options.ConfigFile = strings.TrimPrefix(argument, "--config=")
		case strings.HasPrefix(argument, "--input="):
			options.InputFile = strings.TrimPrefix(argument, "--input=")
		case strings.HasPrefix(argument, "-"):
			return CLIOptions{}, bridgeError("invalid_cli", "unknown option")
		default:
			if options.Command != "" {
				return CLIOptions{}, bridgeError("invalid_cli", "exactly one command is allowed")
			}
			options.Command = argument
		}
	}
	if options.Help {
		return options, nil
	}
	if options.Command == "" {
		return CLIOptions{}, bridgeError("invalid_cli", "a command is required")
	}
	if options.ConfigFile == "" {
		return CLIOptions{}, bridgeError("invalid_cli", "--config is required")
	}
	return options, nil
}

func readInput(filename string, stdin *bufio.Reader) (Input, error) {
	var reader io.Reader = stdin
	var file *os.File
	if filename != "-" {
		var err error
		file, err = os.Open(filename)
		if err != nil {
			return Input{}, bridgeError("invalid_input", "cannot open JSON input file")
		}
		defer file.Close()
		reader = file
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	if err != nil || len(data) > maxInputBytes {
		return Input{}, bridgeError("invalid_input", "JSON input exceeds 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input Input
	if err := decoder.Decode(&input); err != nil {
		return Input{}, bridgeError("invalid_input", "input must be one JSON object with known fields")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Input{}, bridgeError("invalid_input", "input must contain exactly one JSON object")
	}
	return input, nil
}

func startupError(command string, err error) Response {
	requestID, _ := normalizeIdentifier("", "req")
	operationID, _ := normalizeIdentifier("", "op")
	return Response{
		SchemaVersion: SchemaVersion,
		OK:            false,
		Command:       command,
		RequestID:     requestID,
		OperationID:   operationID,
		DryRun:        isWriteCommand(command),
		Error:         errorResponse(err),
	}
}

func helpResponse() Response {
	requestID, _ := normalizeIdentifier("", "req")
	operationID, _ := normalizeIdentifier("", "op")
	return Response{
		SchemaVersion: SchemaVersion,
		OK:            true,
		Command:       "help",
		RequestID:     requestID,
		OperationID:   operationID,
		DryRun:        false,
		Result: map[string]any{
			"usage":      "filebrowser-agentctl --config <file> [--input <file|->] [--token-stdin] [--allow-localhost-http] [--apply] <command>",
			"commands":   []string{"ping", "whoami", "capabilities", "sources", "list", "search", "stat", "checksum", "read", "download", "mkdir", "upload-new"},
			"prohibited": []string{"delete", "share", "token management", "user management", "ACL management", "arbitrary HTTP", "shell", "move", "rename", "overwrite"},
		},
	}
}

func writeResponse(writer io.Writer, response Response) {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(response); err != nil {
		_, _ = fmt.Fprintln(writer, `{"schema_version":"filebrowser-agentctl/v1","ok":false,"command":"","request_id":"","operation_id":"","dry_run":false,"error":{"code":"output_failed","message":"could not encode JSON output","retryable":false}}`)
	}
}
