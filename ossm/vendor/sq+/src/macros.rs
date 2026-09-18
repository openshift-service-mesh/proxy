macro_rules! platform {
    { unix => { $($unix:tt)* }, windows => { $($windows:tt)* }, } => {
        if cfg!(unix) {
            #[cfg(unix)] { $($unix)* }
            #[cfg(not(unix))] { unreachable!() }
        } else if cfg!(windows) {
            #[cfg(windows)] { $($windows)* }
            #[cfg(not(windows))] { unreachable!() }
        } else {
            #[cfg(not(any(unix, windows)))] compile_error!("Unsupported platform");
            unreachable!()
        }
    }
}

/// Like `writeln!`, but nicely wraps lines.
///
/// Terminates the process with an error code if writing to the stream
/// fails.
macro_rules! wwriteln {
    {
        stream=$stream: expr
    } => {{
        let stream: &mut dyn std::io::Write = $stream;
        if let Err(e) = writeln!(stream) {
            let mut exit_code = 1;
            // Handle `BrokenPipe` explicitly.
            #[cfg(unix)]
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                // The 7th bit indicates an error.
                exit_code = 128 + libc::SIGPIPE;
            } else {
                eprintln!("Error: {}", e);
            }
            std::process::exit(exit_code);
        }
    }};

    {
        stream=$stream: expr,
        indent=$i: expr,
        $($arg: expr),*
    } => {{
        let stream: &mut dyn std::io::Write = $stream;
        let i = $i;
        crate::output::wrapping::iwwriteln(
            stream,
            i.as_ref(), i.as_ref(),
            format_args!($($arg),*))
    }};

    {
        stream=$stream: expr,
        initial_indent=$ii: expr,
        subsequent_indent=$si: expr,
        $($arg: expr),*
    } => {{
        let stream: &mut dyn std::io::Write = $stream;
        let ii = $ii;
        let si = $si;
        crate::output::wrapping::iwwriteln(
            stream,
            ii.as_ref(), si.as_ref(),
            format_args!($($arg),*))
    }};

    {
        stream=$stream: expr,
        initial_indent=$ii: expr,
        $($arg: expr),*
    } => {{
        let stream: &mut dyn std::io::Write = $stream;
        let ii = $ii;
        let si = format!("{:1$}", "", ii.len());
        crate::output::wrapping::iwwriteln(
            stream, ii.as_ref(), si.as_ref(),
            format_args!($($arg),*))
    }};

    {
        stream=$stream: expr,
        $($arg: expr),*
    } => {{
        let stream: &mut dyn std::io::Write = $stream;
        crate::output::wrapping::wwriteln(
            stream, format_args!($($arg),*))
    }};

    {
        $stream: expr,
        $($arg: expr),*
    } => {
        wwriteln!(stream=$stream, $($arg),*)
    };

    {
        $stream: expr
    } => {
        wwriteln!(stream=$stream)
    };
}

/// Like eprintln, but nicely wraps lines.
macro_rules! weprintln {
    { } => {
        wwriteln!(stream=&mut std::io::stderr())
    };

    {
        indent=$i: expr,
        $($arg: expr),*
    } => {
        wwriteln!(stream=&mut std::io::stderr(),
                  indent=$i,
                  $($arg),*)
    };

    {
        initial_indent=$ii: expr,
        subsequent_indent=$si: expr,
        $($arg: expr),*
    } => {
        wwriteln!(stream=&mut std::io::stderr(),
                  initial_indent=$ii,
                  subsequent_indent=$si,
                  $($arg),*)
    };

    {
        initial_indent=$ii: expr,
        $($arg: expr),*
    } => {
        wwriteln!(stream=&mut std::io::stderr(),
                  initial_indent=$ii,
                  $($arg),*)
    };

    {
        $($arg: expr),*
    } => {
        wwriteln!(stream=&mut std::io::stderr(), $($arg),*)
    };
}

/// Like weprintln, but doesn't emit anything in quiet mode.
macro_rules! make_qprintln {
    ($stream: expr, $quiet: expr) => {
        macro_rules! qprintln {
            // XXX: Lot's of repetition due to the fact that nested
            // macros still cannot have repetitions:
            // https://github.com/rust-lang/rust/issues/83527

            // First, with `indent`.
            { indent=$i: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, indent=$i);
                }
            };
            { indent=$i: expr, $a0: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, indent=$i, $a0);
                }
            };
            { indent=$i: expr, $a0: expr, $a1: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, indent=$i, $a0, $a1);
                }
            };
            { indent=$i: expr, $a0: expr, $a1: expr, $a2: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, indent=$i, $a0, $a1, $a2);
                }
            };
            { indent=$i: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, indent=$i, $a0, $a1, $a2, $a3);
                }
            };
            { indent=$i: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, indent=$i, $a0, $a1, $a2, $a3, $a4);
                }
            };
            { indent=$i: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, indent=$i, $a0, $a1, $a2, $a3, $a4, $a5);
                }
            };
            { indent=$i: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr, $a6: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, indent=$i, $a0, $a1, $a2, $a3, $a4, $a5, $a6);
                }
            };
            // Again, with `initial_indent` and `subsequent_indent`.
            { initial_indent=$ii: expr, subsequent_indent=$si: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, subsequent_indent=$si);
                }
            };
            { initial_indent=$ii: expr, subsequent_indent=$si: expr, $a0: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, subsequent_indent=$si, $a0);
                }
            };
            { initial_indent=$ii: expr, subsequent_indent=$si: expr, $a0: expr, $a1: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, subsequent_indent=$si, $a0, $a1);
                }
            };
            { initial_indent=$ii: expr, subsequent_indent=$si: expr, $a0: expr, $a1: expr, $a2: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, subsequent_indent=$si, $a0, $a1, $a2);
                }
            };
            { initial_indent=$ii: expr, subsequent_indent=$si: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, subsequent_indent=$si, $a0, $a1, $a2, $a3);
                }
            };
            { initial_indent=$ii: expr, subsequent_indent=$si: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, subsequent_indent=$si, $a0, $a1, $a2, $a3, $a4);
                }
            };
            { initial_indent=$ii: expr, subsequent_indent=$si: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, subsequent_indent=$si, $a0, $a1, $a2, $a3, $a4, $a5);
                }
            };
            { initial_indent=$ii: expr, subsequent_indent=$si: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr, $a6: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, subsequent_indent=$si, $a0, $a1, $a2, $a3, $a4, $a5, $a6);
                }
            };

            // Again, with `initial_indent`.
            { initial_indent=$ii: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii);
                }
            };
            { initial_indent=$ii: expr, $a0: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, $a0);
                }
            };
            { initial_indent=$ii: expr, $a0: expr, $a1: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, $a0, $a1);
                }
            };
            { initial_indent=$ii: expr, $a0: expr, $a1: expr, $a2: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, $a0, $a1, $a2);
                }
            };
            { initial_indent=$ii: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, $a0, $a1, $a2, $a3);
                }
            };
            { initial_indent=$ii: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, $a0, $a1, $a2, $a3, $a4);
                }
            };
            { initial_indent=$ii: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, $a0, $a1, $a2, $a3, $a4, $a5);
                }
            };
            { initial_indent=$ii: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr, $a6: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, initial_indent=$ii, $a0, $a1, $a2, $a3, $a4, $a5, $a6);
                }
            };

            // Again, without any indent.
            {} => {
                if ! $quiet {
                    wwriteln!(stream=$stream);
                }
            };
            { $a0: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, $a0);
                }
            };
            { $a0: expr, $a1: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, $a0, $a1);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, $a0, $a1, $a2);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr, $a3: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, $a0, $a1, $a2, $a3);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, $a0, $a1, $a2, $a3, $a4);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, $a0, $a1, $a2, $a3, $a4, $a5);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr, $a6: expr } => {
                if ! $quiet {
                    wwriteln!(stream=$stream, $a0, $a1, $a2, $a3, $a4, $a5, $a6);
                }
            };
        }
    };
    ($quiet: expr) => {
        make_qprintln!(&mut std::io::stderr(), $quiet)
    }
}
