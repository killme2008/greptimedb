// Copyright 2023 Greptime Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Arc;

use datafusion_expr::{Expr, LogicalPlan, UserDefinedLogicalNode};
use promql::extension_plan::{
    EmptyMetric, InstantManipulate, RangeManipulate, SeriesDivide, SeriesNormalize,
};

use crate::dist_plan::MergeScanLogicalPlan;

#[allow(dead_code)]
pub enum Commutativity {
    Commutative,
    PartialCommutative,
    ConditionalCommutative(Option<Transformer>),
    TransformedCommutative(Option<Transformer>),
    NonCommutative,
    Unimplemented,
    CheckPartition,
    /// For unrelated plans like DDL
    Unsupported,
}

pub struct Categorizer {}

impl Categorizer {
    pub fn check_plan(plan: &LogicalPlan) -> Commutativity {
        match plan {
            LogicalPlan::Projection(proj) => {
                for expr in &proj.expr {
                    let commutativity = Self::check_expr(expr);
                    if !matches!(commutativity, Commutativity::Commutative) {
                        return commutativity;
                    }
                }
                Commutativity::Commutative
            }
            // TODO(ruihang): Change this to Commutative once Like is supported in substrait
            LogicalPlan::Filter(filter) => Self::check_expr(&filter.predicate),
            LogicalPlan::Window(_) => Commutativity::Unimplemented,
            LogicalPlan::Aggregate(_) => {
                // check all children exprs and uses the strictest level
                Commutativity::Unimplemented
            }
            LogicalPlan::Sort(_) => Commutativity::Unimplemented,
            LogicalPlan::Join(_) => Commutativity::NonCommutative,
            LogicalPlan::CrossJoin(_) => Commutativity::NonCommutative,
            LogicalPlan::Repartition(_) => {
                // unsupported? or non-commutative
                Commutativity::Unimplemented
            }
            LogicalPlan::Union(_) => Commutativity::Unimplemented,
            LogicalPlan::TableScan(_) => Commutativity::CheckPartition,
            LogicalPlan::EmptyRelation(_) => Commutativity::NonCommutative,
            LogicalPlan::Subquery(_) => Commutativity::Unimplemented,
            LogicalPlan::SubqueryAlias(_) => Commutativity::Unimplemented,
            LogicalPlan::Limit(_) => Commutativity::PartialCommutative,
            LogicalPlan::Extension(extension) => {
                Self::check_extension_plan(extension.node.as_ref() as _)
            }
            LogicalPlan::Distinct(_) => Commutativity::PartialCommutative,
            LogicalPlan::Unnest(_) => Commutativity::Commutative,
            LogicalPlan::Statement(_) => Commutativity::Unsupported,
            LogicalPlan::Values(_) => Commutativity::Unsupported,
            LogicalPlan::Explain(_) => Commutativity::Unsupported,
            LogicalPlan::Analyze(_) => Commutativity::Unsupported,
            LogicalPlan::Prepare(_) => Commutativity::Unsupported,
            LogicalPlan::DescribeTable(_) => Commutativity::Unsupported,
            LogicalPlan::Dml(_) => Commutativity::Unsupported,
            LogicalPlan::Ddl(_) => Commutativity::Unsupported,
        }
    }

    pub fn check_extension_plan(plan: &dyn UserDefinedLogicalNode) -> Commutativity {
        match plan.name() {
            name if name == EmptyMetric::name()
                || name == InstantManipulate::name()
                || name == SeriesNormalize::name()
                || name == RangeManipulate::name()
                || name == SeriesDivide::name()
                || name == MergeScanLogicalPlan::name() =>
            {
                Commutativity::Commutative
            }
            _ => Commutativity::Unsupported,
        }
    }

    pub fn check_expr(expr: &Expr) -> Commutativity {
        match expr {
            Expr::Column(_)
            | Expr::ScalarVariable(_, _)
            | Expr::Literal(_)
            | Expr::BinaryExpr(_)
            | Expr::Not(_)
            | Expr::IsNotNull(_)
            | Expr::IsNull(_)
            | Expr::IsTrue(_)
            | Expr::IsFalse(_)
            | Expr::IsNotTrue(_)
            | Expr::IsNotFalse(_)
            | Expr::Negative(_)
            | Expr::Between(_)
            | Expr::Sort(_)
            | Expr::Exists(_) => Commutativity::Commutative,

            Expr::Like(_)
            | Expr::ILike(_)
            | Expr::SimilarTo(_)
            | Expr::IsUnknown(_)
            | Expr::IsNotUnknown(_)
            | Expr::GetIndexedField(_)
            | Expr::Case(_)
            | Expr::Cast(_)
            | Expr::TryCast(_)
            | Expr::ScalarFunction(_)
            | Expr::ScalarUDF(_)
            | Expr::AggregateFunction(_)
            | Expr::WindowFunction(_)
            | Expr::AggregateUDF(_)
            | Expr::InList(_)
            | Expr::InSubquery(_)
            | Expr::ScalarSubquery(_)
            | Expr::Wildcard => Commutativity::Unimplemented,

            Expr::Alias(_, _)
            | Expr::QualifiedWildcard { .. }
            | Expr::GroupingSet(_)
            | Expr::Placeholder(_)
            | Expr::OuterReferenceColumn(_, _) => Commutativity::Unimplemented,
        }
    }
}

pub type Transformer = Arc<dyn Fn(&LogicalPlan) -> Option<LogicalPlan>>;

pub fn partial_commutative_transformer(plan: &LogicalPlan) -> Option<LogicalPlan> {
    Some(plan.clone())
}
