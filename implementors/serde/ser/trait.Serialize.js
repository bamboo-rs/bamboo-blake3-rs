(function() {var implementors = {};
implementors["bamboo_rs_core_ed25519_yasmf"] = [{"text":"impl&lt;H, S&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"bamboo_rs_core_ed25519_yasmf/entry/struct.Entry.html\" title=\"struct bamboo_rs_core_ed25519_yasmf::entry::Entry\">Entry</a>&lt;H, S&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;H: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/borrow/trait.Borrow.html\" title=\"trait core::borrow::Borrow\">Borrow</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.59.0/std/primitive.slice.html\">[</a><a class=\"primitive\" href=\"https://doc.rust-lang.org/1.59.0/std/primitive.u8.html\">u8</a><a class=\"primitive\" href=\"https://doc.rust-lang.org/1.59.0/std/primitive.slice.html\">]</a>&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;S: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/borrow/trait.Borrow.html\" title=\"trait core::borrow::Borrow\">Borrow</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.59.0/std/primitive.slice.html\">[</a><a class=\"primitive\" href=\"https://doc.rust-lang.org/1.59.0/std/primitive.u8.html\">u8</a><a class=\"primitive\" href=\"https://doc.rust-lang.org/1.59.0/std/primitive.slice.html\">]</a>&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;H: <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;S: <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,&nbsp;</span>","synthetic":false,"types":["bamboo_rs_core_ed25519_yasmf::entry::Entry"]},{"text":"impl&lt;B:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/borrow/trait.Borrow.html\" title=\"trait core::borrow::Borrow\">Borrow</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.59.0/std/primitive.slice.html\">[</a><a class=\"primitive\" href=\"https://doc.rust-lang.org/1.59.0/std/primitive.u8.html\">u8</a><a class=\"primitive\" href=\"https://doc.rust-lang.org/1.59.0/std/primitive.slice.html\">]</a>&gt;&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"bamboo_rs_core_ed25519_yasmf/signature/struct.Signature.html\" title=\"struct bamboo_rs_core_ed25519_yasmf::signature::Signature\">Signature</a>&lt;B&gt;","synthetic":false,"types":["bamboo_rs_core_ed25519_yasmf::signature::Signature"]}];
implementors["ed25519"] = [{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"ed25519/struct.Signature.html\" title=\"struct ed25519::Signature\">Signature</a>","synthetic":false,"types":["ed25519::Signature"]}];
implementors["ed25519_dalek"] = [{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"ed25519_dalek/struct.Keypair.html\" title=\"struct ed25519_dalek::Keypair\">Keypair</a>","synthetic":false,"types":["ed25519_dalek::keypair::Keypair"]},{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"ed25519_dalek/struct.PublicKey.html\" title=\"struct ed25519_dalek::PublicKey\">PublicKey</a>","synthetic":false,"types":["ed25519_dalek::public::PublicKey"]},{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"ed25519_dalek/struct.SecretKey.html\" title=\"struct ed25519_dalek::SecretKey\">SecretKey</a>","synthetic":false,"types":["ed25519_dalek::secret::SecretKey"]},{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"ed25519_dalek/struct.ExpandedSecretKey.html\" title=\"struct ed25519_dalek::ExpandedSecretKey\">ExpandedSecretKey</a>","synthetic":false,"types":["ed25519_dalek::secret::ExpandedSecretKey"]}];
implementors["serde_bytes"] = [{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"serde_bytes/struct.Bytes.html\" title=\"struct serde_bytes::Bytes\">Bytes</a>","synthetic":false,"types":["serde_bytes::bytes::Bytes"]},{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"serde_bytes/struct.ByteBuf.html\" title=\"struct serde_bytes::ByteBuf\">ByteBuf</a>","synthetic":false,"types":["serde_bytes::bytebuf::ByteBuf"]}];
implementors["yasmf_hash"] = [{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"yasmf_hash/error/enum.Error.html\" title=\"enum yasmf_hash::error::Error\">Error</a>","synthetic":false,"types":["yasmf_hash::error::Error"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/borrow/trait.Borrow.html\" title=\"trait core::borrow::Borrow\">Borrow</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.59.0/std/primitive.slice.html\">[</a><a class=\"primitive\" href=\"https://doc.rust-lang.org/1.59.0/std/primitive.u8.html\">u8</a><a class=\"primitive\" href=\"https://doc.rust-lang.org/1.59.0/std/primitive.slice.html\">]</a>&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"yasmf_hash/enum.YasmfHash.html\" title=\"enum yasmf_hash::YasmfHash\">YasmfHash</a>&lt;T&gt;","synthetic":false,"types":["yasmf_hash::YasmfHash"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()