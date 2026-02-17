use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    DropOldest,
    DropNewest,
    Block,
}

impl OverflowPolicy {
    pub fn from_env(raw: &str) -> Self {
        match raw.trim().to_lowercase().as_str() {
            "drop_newest" => Self::DropNewest,
            "block" => Self::Block,
            _ => Self::DropOldest,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct BusStats {
    pub published: u64,
    pub consumed: u64,
    pub dropped: u64,
    pub depth: usize,
}

#[derive(Debug)]
pub struct MessageBus {
    queue: VecDeque<String>,
    capacity: usize,
    overflow: OverflowPolicy,
    stats: BusStats,
}

impl MessageBus {
    pub fn new(capacity: usize, overflow: OverflowPolicy) -> Self {
        Self {
            queue: VecDeque::new(),
            capacity: capacity.max(1),
            overflow,
            stats: BusStats::default(),
        }
    }

    pub fn publish(&mut self, message: String) -> bool {
        if self.queue.len() >= self.capacity {
            match self.overflow {
                OverflowPolicy::DropOldest => {
                    self.queue.pop_front();
                    self.stats.dropped += 1;
                }
                OverflowPolicy::DropNewest => {
                    self.stats.dropped += 1;
                    self.stats.depth = self.queue.len();
                    return false;
                }
                OverflowPolicy::Block => {
                    self.stats.dropped += 1;
                    self.stats.depth = self.queue.len();
                    return false;
                }
            }
        }

        self.queue.push_back(message);
        self.stats.published += 1;
        self.stats.depth = self.queue.len();
        true
    }

    pub fn consume(&mut self) -> Option<String> {
        let message = self.queue.pop_front();
        if message.is_some() {
            self.stats.consumed += 1;
        }
        self.stats.depth = self.queue.len();
        message
    }

    pub fn stats(&self) -> BusStats {
        self.stats.clone()
    }
}
