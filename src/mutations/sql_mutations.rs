use super::Mutator;
use rand::Rng;

pub struct SqlMutator {
    keywords: Vec<String>,
    operators: Vec<String>,
}

impl SqlMutator {
    pub fn new() -> Self {
        Self {
            keywords: vec![
                "SELECT".into(),
                "FROM".into(),
                "WHERE".into(),
                "GROUP BY".into(),
                "ORDER BY".into(),
            ],
            operators: vec![
                "=".into(),
                ">".into(),
                "<".into(),
                ">=".into(),
                "<=".into(),
            ],
        }
    }

    fn mutate_keyword(&self, query: &str) -> String {
        let mut rng = rand::thread_rng();
        let new_keyword = &self.keywords[rng.gen_range(0..self.keywords.len())];
        query.replacen(&self.keywords[0], new_keyword, 1)
    }

    fn mutate_operator(&self, query: &str) -> String {
        let mut rng = rand::thread_rng();
        let new_op = &self.operators[rng.gen_range(0..self.operators.len())];
        query.replacen(&self.operators[0], new_op, 1)
    }
}

impl Mutator for SqlMutator {
    fn mutate(&self, input: &[u8]) -> Vec<u8> {
        let query = String::from_utf8_lossy(input);
        let mutated = match rand::random::<u8>() % 3 {
            0 => self.mutate_keyword(&query),
            1 => self.mutate_operator(&query),
            _ => self.inject_random_condition(&query),
        };
        mutated.into_bytes()
    }

    fn is_valid(&self, input: &[u8]) -> bool {
        if let Ok(query) = String::from_utf8(input.to_vec()) {
            query.contains("SELECT") && query.contains("FROM") // basic checks
        } else {
            false
        }
    }
}
