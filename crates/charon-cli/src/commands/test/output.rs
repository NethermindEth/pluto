//! Test result output formatting and file I/O.

use super::types::{AllCategoriesResult, TestCategoryResult, TestResultError};
use crate::{
    ascii::{append_score, get_category_ascii, get_score_ascii},
    error::{CliError, Result},
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
};

/// Writes test results to a writer (stdout or file).
pub fn write_result_to_writer<W: Write>(result: &TestCategoryResult, writer: &mut W) -> Result<()> {
    let mut lines = Vec::new();

    // Add category ASCII art
    let category_ascii = get_category_ascii(&result.category_name);
    for line in category_ascii {
        lines.push(line.to_string());
    }

    // Append score ASCII if present
    if let Some(score) = result.score {
        let score_ascii = get_score_ascii(score);
        lines = append_score(lines, score_ascii);
    }

    // Add test results
    lines.push(String::new());
    lines.push(format!("{:<64}{}", "TEST NAME", "RESULT"));

    let mut suggestions = Vec::new();

    // Sort targets by name for consistent output
    let mut targets: Vec<_> = result.targets.iter().collect();
    targets.sort_by_key(|(name, _)| *name);

    for (target, test_results) in targets {
        if !target.is_empty() && !test_results.is_empty() {
            lines.push(String::new());
            lines.push(target.clone());
        }

        for test_result in test_results {
            let mut test_output = format!("{:<64}", test_result.name);

            // Add measurement if present
            if !test_result.measurement.is_empty() {
                // Trim trailing spaces equal to measurement length + 1
                let trim_len = test_result.measurement.len() + 1;
                let current_len = test_output.len();
                if current_len >= trim_len {
                    test_output.truncate(current_len - trim_len);
                }
                test_output.push_str(&test_result.measurement);
                test_output.push(' ');
            }

            // Add verdict
            test_output.push_str(&test_result.verdict.to_string());

            // Add suggestion if present
            if !test_result.suggestion.is_empty() {
                suggestions.push(test_result.suggestion.clone());
            }

            // Add error if present
            if let Some(err_msg) = test_result.error.message() {
                test_output.push_str(" - ");
                test_output.push_str(err_msg);
            }

            lines.push(test_output);
        }
    }

    // Add suggestions section
    if !suggestions.is_empty() {
        lines.push(String::new());
        lines.push("SUGGESTED IMPROVEMENTS".to_string());
        lines.extend(suggestions);
    }

    // Add execution time
    lines.push(String::new());
    if let Some(exec_time) = result.execution_time {
        lines.push(exec_time.to_string());
    }

    // Write all lines
    lines.push(String::new());
    for line in lines {
        writeln!(writer, "{}", line)?;
    }

    Ok(())
}

/// Writes test results to a JSON file.
pub fn write_result_to_file(result: &TestCategoryResult, path: &Path) -> Result<()> {
    // Open or create the file
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|e| CliError::Io {
            source: e,
            context: format!("failed to open file: {}", path.display()),
        })?;

    // Read existing content or default to empty structure
    let metadata = file.metadata().map_err(|e| CliError::Io {
        source: e,
        context: "failed to get file metadata".to_string(),
    })?;

    let mut all_results: AllCategoriesResult = if metadata.len() == 0 {
        AllCategoriesResult::default()
    } else {
        serde_json::from_reader(&file).map_err(|e| CliError::Json {
            source: e,
            context: "failed to parse existing JSON file".to_string(),
        })?
    };

    // Update the appropriate category
    match result.category_name.as_str() {
        "peers" => all_results.peers = Some(result.clone()),
        "beacon" => all_results.beacon = Some(result.clone()),
        "validator" => all_results.validator = Some(result.clone()),
        "mev" => all_results.mev = Some(result.clone()),
        "infra" => all_results.infra = Some(result.clone()),
        _ => {
            return Err(CliError::Other(format!(
                "unknown category: {}",
                result.category_name
            )));
        }
    }

    // Write to a temp file
    let temp_path = path.with_extension("json.tmp");
    let mut temp_file = File::create(&temp_path).map_err(|e| CliError::Io {
        source: e,
        context: format!("failed to create temp file: {}", temp_path.display()),
    })?;

    serde_json::to_writer_pretty(&mut temp_file, &all_results).map_err(|e| CliError::Json {
        source: e,
        context: "failed to write JSON to temp file".to_string(),
    })?;

    temp_file.sync_all().map_err(|e| CliError::Io {
        source: e,
        context: "failed to sync temp file".to_string(),
    })?;

    drop(temp_file);

    // Rename temp file to target file
    std::fs::rename(&temp_path, path).map_err(|e| CliError::Io {
        source: e,
        context: format!(
            "failed to rename {} to {}",
            temp_path.display(),
            path.display()
        ),
    })?;

    Ok(())
}

/// Helper to check if quiet mode requires output-json.
pub fn must_output_to_file_on_quiet(quiet: bool, output_json: &str) -> Result<()> {
    if quiet && output_json.is_empty() {
        Err(CliError::Other(
            "on --quiet, an --output-json is required".to_string(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test::types::{CategoryScore, Duration, TestResult, TestVerdict};
    use std::time::Duration as StdDuration;

    #[test]
    fn test_write_result_to_writer() {
        let mut result = TestCategoryResult::new("peers");
        result.score = Some(CategoryScore::A);
        result.execution_time = Some(Duration::new(StdDuration::from_secs(10)));

        let mut tests = vec![TestResult::new("Ping")];
        tests[0].verdict = TestVerdict::Ok;

        result.targets.insert("peer1".to_string(), tests);

        let mut buf = Vec::new();
        write_result_to_writer(&result, &mut buf).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("TEST NAME"));
        assert!(output.contains("RESULT"));
        assert!(output.contains("Ping"));
        assert!(output.contains("OK"));
    }

    #[test]
    fn test_must_output_to_file_on_quiet() {
        assert!(must_output_to_file_on_quiet(false, "").is_ok());
        assert!(must_output_to_file_on_quiet(true, "out.json").is_ok());
        assert!(must_output_to_file_on_quiet(true, "").is_err());
    }
}
