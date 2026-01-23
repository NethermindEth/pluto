//! Test scoring and evaluation logic.

use super::types::{CategoryScore, Duration, TestCaseName, TestResult, TestVerdict};
use std::{collections::HashMap, time::Duration as StdDuration};

/// Calculates the overall score for a list of test results.
pub fn calculate_score(results: &[TestResult]) -> CategoryScore {
    // TODO: More elaborate calculation with weights
    let mut avg = 0i32;

    for test in results {
        match test.verdict {
            TestVerdict::Poor => return CategoryScore::C,
            TestVerdict::Good => avg += 1,
            TestVerdict::Avg => avg -= 1,
            TestVerdict::Fail => {
                if !test.is_acceptable {
                    return CategoryScore::C;
                }
                continue;
            }
            TestVerdict::Ok | TestVerdict::Skip => continue,
        }
    }

    if avg < 0 {
        CategoryScore::B
    } else {
        CategoryScore::A
    }
}

/// Evaluates RTT (Round Trip Time) and assigns a verdict based on thresholds.
pub fn evaluate_rtt(
    rtt: StdDuration,
    mut result: TestResult,
    avg_threshold: StdDuration,
    poor_threshold: StdDuration,
) -> TestResult {
    if rtt.is_zero() || rtt > poor_threshold {
        result.verdict = TestVerdict::Poor;
    } else if rtt > avg_threshold {
        result.verdict = TestVerdict::Avg;
    } else {
        result.verdict = TestVerdict::Good;
    }

    result.measurement = Duration::new(rtt).round().to_string();
    result
}

/// Evaluates highest RTT from a channel and assigns a verdict.
pub fn evaluate_highest_rtt(
    rtts: Vec<StdDuration>,
    result: TestResult,
    avg_threshold: StdDuration,
    poor_threshold: StdDuration,
) -> TestResult {
    let highest_rtt = rtts.into_iter().max().unwrap_or_default();
    evaluate_rtt(highest_rtt, result, avg_threshold, poor_threshold)
}

/// Filters tests based on configuration.
pub fn filter_tests(
    supported: &HashMap<TestCaseName, ()>,
    test_cases: Option<&[String]>,
) -> Vec<TestCaseName> {
    match test_cases {
        None => supported.keys().cloned().collect(),
        Some(cases) => {
            let mut filtered = Vec::new();
            for case in cases {
                for supported_case in supported.keys() {
                    if &supported_case.name == case {
                        filtered.push(supported_case.clone());
                    }
                }
            }
            filtered
        }
    }
}

/// Sorts tests by their order field.
pub fn sort_tests(tests: &mut [TestCaseName]) {
    tests.sort_by_key(|t| t.order);
}

/// Lists test case names as strings.
pub fn list_test_cases(cases: &HashMap<TestCaseName, ()>) -> Vec<String> {
    cases.keys().map(|tc| tc.name.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_score() {
        let mut results = vec![
            TestResult {
                name: "test1".to_string(),
                verdict: TestVerdict::Good,
                measurement: String::new(),
                suggestion: String::new(),
                error: super::super::types::TestResultError::empty(),
                is_acceptable: false,
            },
            TestResult {
                name: "test2".to_string(),
                verdict: TestVerdict::Good,
                measurement: String::new(),
                suggestion: String::new(),
                error: super::super::types::TestResultError::empty(),
                is_acceptable: false,
            },
        ];

        assert_eq!(calculate_score(&results), CategoryScore::A);

        results.push(TestResult {
            name: "test3".to_string(),
            verdict: TestVerdict::Poor,
            measurement: String::new(),
            suggestion: String::new(),
            error: super::super::types::TestResultError::empty(),
            is_acceptable: false,
        });

        assert_eq!(calculate_score(&results), CategoryScore::C);
    }

    #[test]
    fn test_evaluate_rtt() {
        let result = TestResult::new("test");
        let avg = StdDuration::from_millis(50);
        let poor = StdDuration::from_millis(240);

        // Good
        let res = evaluate_rtt(StdDuration::from_millis(30), result.clone(), avg, poor);
        assert_eq!(res.verdict, TestVerdict::Good);

        // Avg
        let res = evaluate_rtt(StdDuration::from_millis(100), result.clone(), avg, poor);
        assert_eq!(res.verdict, TestVerdict::Avg);

        // Poor
        let res = evaluate_rtt(StdDuration::from_millis(300), result, avg, poor);
        assert_eq!(res.verdict, TestVerdict::Poor);
    }

    #[test]
    fn test_sort_tests() {
        let mut tests = vec![
            TestCaseName::new("test3", 3),
            TestCaseName::new("test1", 1),
            TestCaseName::new("test2", 2),
        ];

        sort_tests(&mut tests);

        assert_eq!(tests[0].name, "test1");
        assert_eq!(tests[1].name, "test2");
        assert_eq!(tests[2].name, "test3");
    }
}
