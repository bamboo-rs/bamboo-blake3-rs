(function() {var implementors = {};
implementors["curve25519_dalek"] = [{"text":"impl&lt;'a, 'b&gt; Add&lt;&amp;'b Scalar&gt; for &amp;'a Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'b&gt; Add&lt;&amp;'b Scalar&gt; for Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'a&gt; Add&lt;Scalar&gt; for &amp;'a Scalar","synthetic":false,"types":[]},{"text":"impl Add&lt;Scalar&gt; for Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'a, 'b&gt; Add&lt;&amp;'b EdwardsPoint&gt; for &amp;'a EdwardsPoint","synthetic":false,"types":[]},{"text":"impl&lt;'b&gt; Add&lt;&amp;'b EdwardsPoint&gt; for EdwardsPoint","synthetic":false,"types":[]},{"text":"impl&lt;'a&gt; Add&lt;EdwardsPoint&gt; for &amp;'a EdwardsPoint","synthetic":false,"types":[]},{"text":"impl Add&lt;EdwardsPoint&gt; for EdwardsPoint","synthetic":false,"types":[]},{"text":"impl&lt;'a, 'b&gt; Add&lt;&amp;'b RistrettoPoint&gt; for &amp;'a RistrettoPoint","synthetic":false,"types":[]},{"text":"impl&lt;'b&gt; Add&lt;&amp;'b RistrettoPoint&gt; for RistrettoPoint","synthetic":false,"types":[]},{"text":"impl&lt;'a&gt; Add&lt;RistrettoPoint&gt; for &amp;'a RistrettoPoint","synthetic":false,"types":[]},{"text":"impl Add&lt;RistrettoPoint&gt; for RistrettoPoint","synthetic":false,"types":[]}];
implementors["typenum"] = [{"text":"impl&lt;I:&nbsp;Integer&gt; Add&lt;I&gt; for Z0","synthetic":false,"types":[]},{"text":"impl&lt;U:&nbsp;Unsigned + NonZero&gt; Add&lt;Z0&gt; for PInt&lt;U&gt;","synthetic":false,"types":[]},{"text":"impl&lt;U:&nbsp;Unsigned + NonZero&gt; Add&lt;Z0&gt; for NInt&lt;U&gt;","synthetic":false,"types":[]},{"text":"impl&lt;Ul:&nbsp;Unsigned + NonZero, Ur:&nbsp;Unsigned + NonZero&gt; Add&lt;PInt&lt;Ur&gt;&gt; for PInt&lt;Ul&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: Add&lt;Ur&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;Ul as Add&lt;Ur&gt;&gt;::Output: Unsigned + NonZero,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;Ul:&nbsp;Unsigned + NonZero, Ur:&nbsp;Unsigned + NonZero&gt; Add&lt;NInt&lt;Ur&gt;&gt; for NInt&lt;Ul&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: Add&lt;Ur&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;Ul as Add&lt;Ur&gt;&gt;::Output: Unsigned + NonZero,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;Ul:&nbsp;Unsigned + NonZero, Ur:&nbsp;Unsigned + NonZero&gt; Add&lt;NInt&lt;Ur&gt;&gt; for PInt&lt;Ul&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: Cmp&lt;Ur&gt; + PrivateIntegerAdd&lt;&lt;Ul as Cmp&lt;Ur&gt;&gt;::Output, Ur&gt;,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;Ul:&nbsp;Unsigned + NonZero, Ur:&nbsp;Unsigned + NonZero&gt; Add&lt;PInt&lt;Ur&gt;&gt; for NInt&lt;Ul&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ur: Cmp&lt;Ul&gt; + PrivateIntegerAdd&lt;&lt;Ur as Cmp&lt;Ul&gt;&gt;::Output, Ul&gt;,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl Add&lt;B0&gt; for UTerm","synthetic":false,"types":[]},{"text":"impl&lt;U:&nbsp;Unsigned, B:&nbsp;Bit&gt; Add&lt;B0&gt; for UInt&lt;U, B&gt;","synthetic":false,"types":[]},{"text":"impl Add&lt;B1&gt; for UTerm","synthetic":false,"types":[]},{"text":"impl&lt;U:&nbsp;Unsigned&gt; Add&lt;B1&gt; for UInt&lt;U, B0&gt;","synthetic":false,"types":[]},{"text":"impl&lt;U:&nbsp;Unsigned&gt; Add&lt;B1&gt; for UInt&lt;U, B1&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;U: Add&lt;B1&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;Add1&lt;U&gt;: Unsigned,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;U:&nbsp;Unsigned&gt; Add&lt;U&gt; for UTerm","synthetic":false,"types":[]},{"text":"impl&lt;U:&nbsp;Unsigned, B:&nbsp;Bit&gt; Add&lt;UTerm&gt; for UInt&lt;U, B&gt;","synthetic":false,"types":[]},{"text":"impl&lt;Ul:&nbsp;Unsigned, Ur:&nbsp;Unsigned&gt; Add&lt;UInt&lt;Ur, B0&gt;&gt; for UInt&lt;Ul, B0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: Add&lt;Ur&gt;,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;Ul:&nbsp;Unsigned, Ur:&nbsp;Unsigned&gt; Add&lt;UInt&lt;Ur, B1&gt;&gt; for UInt&lt;Ul, B0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: Add&lt;Ur&gt;,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;Ul:&nbsp;Unsigned, Ur:&nbsp;Unsigned&gt; Add&lt;UInt&lt;Ur, B0&gt;&gt; for UInt&lt;Ul, B1&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: Add&lt;Ur&gt;,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;Ul:&nbsp;Unsigned, Ur:&nbsp;Unsigned&gt; Add&lt;UInt&lt;Ur, B1&gt;&gt; for UInt&lt;Ul, B1&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: Add&lt;Ur&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;Sum&lt;Ul, Ur&gt;: Add&lt;B1&gt;,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl Add&lt;ATerm&gt; for ATerm","synthetic":false,"types":[]},{"text":"impl&lt;Al, Vl, Ar, Vr&gt; Add&lt;TArr&lt;Vr, Ar&gt;&gt; for TArr&lt;Vl, Al&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Al: Add&lt;Ar&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;Vl: Add&lt;Vr&gt;,&nbsp;</span>","synthetic":false,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()