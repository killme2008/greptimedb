(function() {var type_impls = {
"common_time":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-GenericRange%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#34-141\">source</a><a href=\"#impl-GenericRange%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialOrd.html\" title=\"trait core::cmp::PartialOrd\">PartialOrd</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.and\" class=\"method\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#39-67\">source</a><h4 class=\"code-header\">pub fn <a href=\"common_time/range/struct.GenericRange.html#tymethod.and\" class=\"fn\">and</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;) -&gt; <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h4></section></summary><div class=\"docblock\"><p>Computes the AND’ed range with other.  </p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.or\" class=\"method\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#73-108\">source</a><h4 class=\"code-header\">pub fn <a href=\"common_time/range/struct.GenericRange.html#tymethod.or\" class=\"fn\">or</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;) -&gt; <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h4></section></summary><div class=\"docblock\"><p>Compute the OR’ed range of two ranges.\nNotice: this method does not compute the exact OR’ed operation for simplicity.\nFor example, <code>[1, 2)</code> or’ed with <code>[4, 5)</code> will produce <code>[1, 5)</code>\ninstead of <code>[1, 2) ∪ [4, 5)</code></p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.intersects\" class=\"method\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#111-113\">source</a><h4 class=\"code-header\">pub fn <a href=\"common_time/range/struct.GenericRange.html#tymethod.intersects\" class=\"fn\">intersects</a>(&amp;self, target: &amp;<a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class=\"docblock\"><p>Checks if current range intersect with target.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.empty\" class=\"method\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#116-121\">source</a><h4 class=\"code-header\">pub fn <a href=\"common_time/range/struct.GenericRange.html#tymethod.empty\" class=\"fn\">empty</a>() -&gt; <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h4></section></summary><div class=\"docblock\"><p>Create an empty range.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.from_optional\" class=\"method\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#126-140\">source</a><h4 class=\"code-header\">fn <a href=\"common_time/range/struct.GenericRange.html#tymethod.from_optional\" class=\"fn\">from_optional</a>(start: <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;T&gt;, end: <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;T&gt;) -&gt; <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h4></section></summary><div class=\"docblock\"><p>Create GenericRange from optional start and end.\nIf the present value of start &gt;= the present value of end, it will return an empty range\nwith the default value of <code>T</code>.</p>\n</div></details></div></details>",0,"common_time::range::TimestampRange","common_time::range::RangeMillis"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-GenericRange%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#143-185\">source</a><a href=\"#impl-GenericRange%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.new\" class=\"method\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#147-154\">source</a><h4 class=\"code-header\">pub fn <a href=\"common_time/range/struct.GenericRange.html#tymethod.new\" class=\"fn\">new</a>&lt;U: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialOrd.html\" title=\"trait core::cmp::PartialOrd\">PartialOrd</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;T&gt;&gt;(start: U, end: U) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;&gt;</h4></section></summary><div class=\"docblock\"><p>Creates a new range that contains values in <code>[start, end)</code>.</p>\n<p>Returns <code>None</code> if <code>start</code> &gt; <code>end</code>.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.min_to_max\" class=\"method\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#157-162\">source</a><h4 class=\"code-header\">pub fn <a href=\"common_time/range/struct.GenericRange.html#tymethod.min_to_max\" class=\"fn\">min_to_max</a>() -&gt; <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h4></section></summary><div class=\"docblock\"><p>Return a range containing all possible values.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.start\" class=\"method\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#166-168\">source</a><h4 class=\"code-header\">pub fn <a href=\"common_time/range/struct.GenericRange.html#tymethod.start\" class=\"fn\">start</a>(&amp;self) -&gt; &amp;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;T&gt;</h4></section></summary><div class=\"docblock\"><p>Returns the lower bound of the range (inclusive).</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.end\" class=\"method\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#172-174\">source</a><h4 class=\"code-header\">pub fn <a href=\"common_time/range/struct.GenericRange.html#tymethod.end\" class=\"fn\">end</a>(&amp;self) -&gt; &amp;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;T&gt;</h4></section></summary><div class=\"docblock\"><p>Returns the upper bound of the range (exclusive).</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.contains\" class=\"method\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#177-184\">source</a><h4 class=\"code-header\">pub fn <a href=\"common_time/range/struct.GenericRange.html#tymethod.contains\" class=\"fn\">contains</a>&lt;U: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialOrd.html\" title=\"trait core::cmp::PartialOrd\">PartialOrd</a>&lt;T&gt;&gt;(&amp;self, target: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;U</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class=\"docblock\"><p>Returns true if <code>timestamp</code> is contained in the range.</p>\n</div></details></div></details>",0,"common_time::range::TimestampRange","common_time::range::RangeMillis"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-GenericRange%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#187-196\">source</a><a href=\"#impl-GenericRange%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialOrd.html\" title=\"trait core::cmp::PartialOrd\">PartialOrd</a>&gt; <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.is_empty\" class=\"method\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#190-195\">source</a><h4 class=\"code-header\">pub fn <a href=\"common_time/range/struct.GenericRange.html#tymethod.is_empty\" class=\"fn\">is_empty</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class=\"docblock\"><p>Returns true if the range contains no timestamps.</p>\n</div></details></div></details>",0,"common_time::range::TimestampRange","common_time::range::RangeMillis"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-GenericRange%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#impl-Debug-for-GenericRange%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/nightly/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","common_time::range::TimestampRange","common_time::range::RangeMillis"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-GenericRange%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#impl-PartialEq-for-GenericRange%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>self</code> and <code>other</code> values to be equal, and is used\nby <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cmp.rs.html#242\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>!=</code>. The default implementation is almost always\nsufficient, and should not be overridden without very good reason.</div></details></div></details>","PartialEq","common_time::range::TimestampRange","common_time::range::RangeMillis"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Serialize-for-GenericRange%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#impl-Serialize-for-GenericRange%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#method.serialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serialize.html#tymethod.serialize\" class=\"fn\">serialize</a>&lt;__S&gt;(&amp;self, __serializer: __S) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;__S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serializer.html#associatedtype.Ok\" title=\"type serde::ser::Serializer::Ok\">Ok</a>, __S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serializer.html#associatedtype.Error\" title=\"type serde::ser::Serializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __S: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>,</div></h4></section></summary><div class='docblock'>Serialize this value into the given Serde serializer. <a href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serialize.html#tymethod.serialize\">Read more</a></div></details></div></details>","Serialize","common_time::range::TimestampRange","common_time::range::RangeMillis"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Deserialize%3C'de%3E-for-GenericRange%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#impl-Deserialize%3C'de%3E-for-GenericRange%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'de, T&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.deserialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#method.deserialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.193/serde/de/trait.Deserialize.html#tymethod.deserialize\" class=\"fn\">deserialize</a>&lt;__D&gt;(__deserializer: __D) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, __D::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.193/serde/de/trait.Deserializer.html#associatedtype.Error\" title=\"type serde::de::Deserializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __D: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;,</div></h4></section></summary><div class='docblock'>Deserialize this value from the given Serde deserializer. <a href=\"https://docs.rs/serde/1.0.193/serde/de/trait.Deserialize.html#tymethod.deserialize\">Read more</a></div></details></div></details>","Deserialize<'de>","common_time::range::TimestampRange","common_time::range::RangeMillis"],["<section id=\"impl-Eq-for-GenericRange%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#impl-Eq-for-GenericRange%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h3></section>","Eq","common_time::range::TimestampRange","common_time::range::RangeMillis"],["<section id=\"impl-StructuralPartialEq-for-GenericRange%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#impl-StructuralPartialEq-for-GenericRange%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralPartialEq.html\" title=\"trait core::marker::StructuralPartialEq\">StructuralPartialEq</a> for <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h3></section>","StructuralPartialEq","common_time::range::TimestampRange","common_time::range::RangeMillis"],["<section id=\"impl-StructuralEq-for-GenericRange%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#impl-StructuralEq-for-GenericRange%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralEq.html\" title=\"trait core::marker::StructuralEq\">StructuralEq</a> for <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h3></section>","StructuralEq","common_time::range::TimestampRange","common_time::range::RangeMillis"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-GenericRange%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#impl-Clone-for-GenericRange%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","common_time::range::TimestampRange","common_time::range::RangeMillis"],["<section id=\"impl-Copy-for-GenericRange%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#impl-Copy-for-GenericRange%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h3></section>","Copy","common_time::range::TimestampRange","common_time::range::RangeMillis"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Hash-for-GenericRange%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#impl-Hash-for-GenericRange%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"common_time/range/struct.GenericRange.html\" title=\"struct common_time::range::GenericRange\">GenericRange</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.hash\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/common_time/range.rs.html#28\">source</a><a href=\"#method.hash\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html#tymethod.hash\" class=\"fn\">hash</a>&lt;__H: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\">Hasher</a>&gt;(&amp;self, state: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut __H</a>)</h4></section></summary><div class='docblock'>Feeds this value into the given <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\"><code>Hasher</code></a>. <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html#tymethod.hash\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.hash_slice\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.3.0\">1.3.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/hash/mod.rs.html#238-240\">source</a></span><a href=\"#method.hash_slice\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html#method.hash_slice\" class=\"fn\">hash_slice</a>&lt;H&gt;(data: &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.slice.html\">[Self]</a>, state: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut H</a>)<div class=\"where\">where\n    H: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\">Hasher</a>,\n    Self: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h4></section></summary><div class='docblock'>Feeds a slice of this type into the given <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\"><code>Hasher</code></a>. <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html#method.hash_slice\">Read more</a></div></details></div></details>","Hash","common_time::range::TimestampRange","common_time::range::RangeMillis"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()