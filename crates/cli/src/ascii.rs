//! ASCII art helpers for CLI output.
//!
//! Generator used: https://patorjk.com/software/taag/#p=display&f=Big

use crate::commands::test::CategoryScore;

/// ASCII art for peers category.
pub const PEERS_ASCII: &str = r#"  ____                                                          
 |  __ \                                                        
 | |__) |___   ___  _ __  ___                                   
 |  ___// _ \ / _ \| '__|/ __|                                  
 | |   |  __/|  __/| |   \__ \                                  
 |_|    \___| \___||_|   |___/                                  
"#;

/// ASCII art for beacon category.
pub const BEACON_ASCII: &str = r#"  ____                                                          
 |  _ \                                                         
 | |_) |  ___   __ _   ___  ___   _ __                          
 |  _ <  / _ \ / _` | / __|/ _ \ | '_ \                         
 | |_) ||  __/| (_| || (__| (_) || | | |                        
 |____/  \___| \__,_| \___|\___/ |_| |_|                        
"#;

/// ASCII art for validator category.
pub const VALIDATOR_ASCII: &str = r#" __      __     _  _      _         _                           
 \ \    / /    | |(_,    | |       | |                          
  \ \  / /__ _ | | _   __| |  __ _ | |_  ___   _ __             
   \ \/ // _` || || | / _` | / _` || __|/ _ \ | '__|            
    \  /| (_| || || || (_| || (_| || |_| (_) || |               
     \/  \__,_||_||_| \__,_| \__,_| \__|\___/ |_|               
"#;

/// ASCII art for MEV category.
pub const MEV_ASCII: &str = r#" __  __ ________      __                                        
|  \/  |  ____\ \    / /                                        
| \  / | |__   \ \  / /                                         
| |\/| |  __|   \ \/ /                                          
| |  | | |____   \  /                                           
|_|  |_|______|   \/                                            
"#;

/// ASCII art for infra category.
pub const INFRA_ASCII: &str = r#" _____        __                                                
|_   _|      / _|                                               
  | |  _ __ | |_ _ __ __ _                                      
  | | | '_ \|  _| '__/ _` |                                     
 _| |_| | | | | | | | (_| |                                     
|_____|_| |_|_| |_|  \__,_|                                     
"#;

/// ASCII art for default/unknown category.
pub const CATEGORY_DEFAULT_ASCII: &str = r#"                                                                
                                                                
                                                                
                                                                
                                                                
                                                                
"#;

/// ASCII art for score A.
pub const SCORE_A_ASCII: &str = r#"          
    /\    
   /  \   
  / /\ \  
 / ____ \ 
/_/    \_\
"#;

/// ASCII art for score B.
pub const SCORE_B_ASCII: &str = r#" ____     
|  _ \    
| |_) |   
|  _ <    
| |_) |   
|____/    
"#;

/// ASCII art for score C.
pub const SCORE_C_ASCII: &str = r#"   ____     
 / ____|   
| |       
| |       
| |____   
 \_____|  
"#;

/// Returns the ASCII art for a given category name.
pub fn get_category_ascii(category: &str) -> &'static str {
    match category {
        "peers" => PEERS_ASCII,
        "beacon" => BEACON_ASCII,
        "validator" => VALIDATOR_ASCII,
        "mev" => MEV_ASCII,
        "infra" => INFRA_ASCII,
        _ => CATEGORY_DEFAULT_ASCII,
    }
}

#[inline]
/// Returns the ASCII art for a given score.
pub fn get_score_ascii(score: CategoryScore) -> &'static str {
    match score {
        CategoryScore::A => SCORE_A_ASCII,
        CategoryScore::B => SCORE_B_ASCII,
        CategoryScore::C => SCORE_C_ASCII,
    }
}

/// Appends score ASCII to category ASCII lines.
pub fn append_score(mut category_lines: Vec<String>, score_ascii: &str) -> Vec<String> {
    let score_lines: Vec<&str> = score_ascii.lines().collect();
    for (i, line) in category_lines.iter_mut().enumerate() {
        if i < score_lines.len() {
            line.push_str(score_lines[i]);
        }
    }
    category_lines
}
