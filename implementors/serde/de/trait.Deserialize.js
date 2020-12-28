(function() {var implementors = {};
implementors["bamboo_core"] = [{"text":"impl&lt;'de, H, S&gt; Deserialize&lt;'de&gt; for Entry&lt;H, S&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;H: Borrow&lt;[u8]&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;S: Borrow&lt;[u8]&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;H: From&lt;Vec&lt;u8&gt;&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;S: From&lt;Vec&lt;u8&gt;&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;H: Deserialize&lt;'de&gt;,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;'de, B:&nbsp;Borrow&lt;[u8]&gt;&gt; Deserialize&lt;'de&gt; for Signature&lt;B&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;B: From&lt;Vec&lt;u8&gt;&gt;,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;'de, T:&nbsp;Borrow&lt;[u8]&gt;&gt; Deserialize&lt;'de&gt; for YamfHash&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: From&lt;Vec&lt;u8&gt;&gt;,&nbsp;</span>","synthetic":false,"types":[]}];
implementors["ed25519"] = [{"text":"impl&lt;'de&gt; Deserialize&lt;'de&gt; for Signature","synthetic":false,"types":[]}];
implementors["ed25519_dalek"] = [{"text":"impl&lt;'d&gt; Deserialize&lt;'d&gt; for Keypair","synthetic":false,"types":[]},{"text":"impl&lt;'d&gt; Deserialize&lt;'d&gt; for PublicKey","synthetic":false,"types":[]},{"text":"impl&lt;'d&gt; Deserialize&lt;'d&gt; for SecretKey","synthetic":false,"types":[]},{"text":"impl&lt;'d&gt; Deserialize&lt;'d&gt; for ExpandedSecretKey","synthetic":false,"types":[]}];
implementors["serde_bytes"] = [{"text":"impl&lt;'a, 'de: 'a&gt; Deserialize&lt;'de&gt; for &amp;'a Bytes","synthetic":false,"types":[]},{"text":"impl&lt;'de&gt; Deserialize&lt;'de&gt; for ByteBuf","synthetic":false,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()