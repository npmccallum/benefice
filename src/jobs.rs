// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use uuid::Uuid;

use super::auth::User;
use super::job::Job;

#[derive(Default)]
pub struct Jobs {
    pub u2i: HashMap<User, Uuid>,
    pub i2j: HashMap<Uuid, Arc<RwLock<Job>>>,
}

impl Jobs {
    pub fn by_user(&self, user: &User) -> Option<&Arc<RwLock<Job>>> {
        self.u2i.get(user).and_then(|uuid| self.i2j.get(uuid))
    }
}
