use std::collections::HashMap;
#[derive(Clone, Debug)]
pub struct GenerationOutputs {
    pub new_state: HashMap<i32, i32>,
}
