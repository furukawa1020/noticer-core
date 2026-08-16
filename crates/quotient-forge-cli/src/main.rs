use std::process::ExitCode;

fn main() -> ExitCode {
    match quotient_forge_cli::run_from(std::env::args_os().skip(1)) {
        Ok(Some(summary)) => {
            println!(
                "判定: {}\n{}\n成果物: {}",
                summary.status,
                summary.message_ja,
                summary.output.display()
            );
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("エラー: {error}");
            ExitCode::from(2)
        }
    }
}
