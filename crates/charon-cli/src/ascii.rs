//! ASCII art helpers for CLI output.
//!
//! Generator used: https://patorjk.com/software/taag/#p=display&f=Big

use crate::commands::test::CategoryScore;

/// ASCII art for peers category.
pub fn peers_ascii() -> &'static [&'static str] {
    &[
        "  ____                                                          ",
        " |  __ \\                                                        ",
        " | |__) |___   ___  _ __  ___                                   ",
        " |  ___// _ \\ / _ \\| '__|/ __|                                  ",
        " | |   |  __/|  __/| |   \\__ \\                                  ",
        " |_|    \\___| \\___||_|   |___/                                  ",
    ]
}

/// ASCII art for beacon category.
pub fn beacon_ascii() -> &'static [&'static str] {
    &[
        "  ____                                                          ",
        " |  _ \\                                                         ",
        " | |_) |  ___   __ _   ___  ___   _ __                          ",
        " |  _ <  / _ \\ / _` | / __|/ _ \\ | '_ \\                         ",
        " | |_) ||  __/| (_| || (__| (_) || | | |                        ",
        " |____/  \\___| \\__,_| \\___|\\___/ |_| |_|                        ",
    ]
}

/// ASCII art for validator category.
pub fn validator_ascii() -> &'static [&'static str] {
    &[
        " __      __     _  _      _         _                           ",
        " \\ \\    / /    | |(_,    | |       | |                          ",
        "  \\ \\  / /__ _ | | _   __| |  __ _ | |_  ___   _ __             ",
        "   \\ \\/ // _` || || | / _` | / _` || __|/ _ \\ | '__|            ",
        "    \\  /| (_| || || || (_| || (_| || |_| (_) || |               ",
        "     \\/  \\__,_||_||_| \\__,_| \\__,_| \\__|\\___/ |_|               ",
    ]
}

/// ASCII art for MEV category.
pub fn mev_ascii() -> &'static [&'static str] {
    &[
        " __  __ ________      __                                        ",
        "|  \\/  |  ____\\ \\    / /                                        ",
        "| \\  / | |__   \\ \\  / /                                         ",
        "| |\\/| |  __|   \\ \\/ /                                          ",
        "| |  | | |____   \\  /                                           ",
        "|_|  |_|______|   \\/                                            ",
    ]
}

/// ASCII art for infra category.
pub fn infra_ascii() -> &'static [&'static str] {
    &[
        " _____        __                                                ",
        "|_   _|      / _|                                               ",
        "  | |  _ __ | |_ _ __ __ _                                      ",
        "  | | | '_ \\|  _| '__/ _` |                                     ",
        " _| |_| | | | | | | | (_| |                                     ",
        "|_____|_| |_|_| |_|  \\__,_|                                     ",
    ]
}

/// ASCII art for default/unknown category.
pub fn category_default_ascii() -> &'static [&'static str] {
    &[
        "                                                                ",
        "                                                                ",
        "                                                                ",
        "                                                                ",
        "                                                                ",
        "                                                                ",
    ]
}

/// ASCII art for score A.
pub fn score_a_ascii() -> &'static [&'static str] {
    &[
        "          ",
        "    /\\    ",
        "   /  \\   ",
        "  / /\\ \\  ",
        " / ____ \\ ",
        "/_/    \\_\\",
    ]
}

/// ASCII art for score B.
pub fn score_b_ascii() -> &'static [&'static str] {
    &[
        " ____     ",
        "|  _ \\    ",
        "| |_) |   ",
        "|  _ <    ",
        "| |_) |   ",
        "|____/    ",
    ]
}

/// ASCII art for score C.
pub fn score_c_ascii() -> &'static [&'static str] {
    &[
        "   ____     ",
        " / ____|   ",
        "| |       ",
        "| |       ",
        "| |____   ",
        " \\_____|  ",
    ]
}

/// Returns the ASCII art for a given category name.
pub fn get_category_ascii(category: &str) -> &'static [&'static str] {
    match category {
        "peers" => peers_ascii(),
        "beacon" => beacon_ascii(),
        "validator" => validator_ascii(),
        "mev" => mev_ascii(),
        "infra" => infra_ascii(),
        _ => category_default_ascii(),
    }
}

/// Returns the ASCII art for a given score.
pub fn get_score_ascii(score: CategoryScore) -> &'static [&'static str] {
    match score {
        CategoryScore::A => score_a_ascii(),
        CategoryScore::B => score_b_ascii(),
        CategoryScore::C => score_c_ascii(),
    }
}

/// Appends score ASCII to category ASCII lines.
pub fn append_score(
    mut category_lines: Vec<String>,
    score_lines: &[&str],
) -> Vec<String> {
    for (i, line) in category_lines.iter_mut().enumerate() {
        if i < score_lines.len() {
            line.push_str(score_lines[i]);
        }
    }
    category_lines
}
