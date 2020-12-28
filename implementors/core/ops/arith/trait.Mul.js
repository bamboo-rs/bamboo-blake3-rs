(function() {var implementors = {};
implementors["curve25519_dalek"] = [{"text":"impl&lt;'a, 'b&gt; Mul&lt;&amp;'b Scalar&gt; for &amp;'a Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'b&gt; Mul&lt;&amp;'b Scalar&gt; for Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'a&gt; Mul&lt;Scalar&gt; for &amp;'a Scalar","synthetic":false,"types":[]},{"text":"impl Mul&lt;Scalar&gt; for Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'b&gt; Mul&lt;&amp;'b Scalar&gt; for MontgomeryPoint","synthetic":false,"types":[]},{"text":"impl&lt;'a&gt; Mul&lt;Scalar&gt; for &amp;'a MontgomeryPoint","synthetic":false,"types":[]},{"text":"impl Mul&lt;Scalar&gt; for MontgomeryPoint","synthetic":false,"types":[]},{"text":"impl&lt;'b&gt; Mul&lt;&amp;'b MontgomeryPoint&gt; for Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'a&gt; Mul&lt;MontgomeryPoint&gt; for &amp;'a Scalar","synthetic":false,"types":[]},{"text":"impl Mul&lt;MontgomeryPoint&gt; for Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'a, 'b&gt; Mul&lt;&amp;'b Scalar&gt; for &amp;'a MontgomeryPoint","synthetic":false,"types":[]},{"text":"impl&lt;'a, 'b&gt; Mul&lt;&amp;'b MontgomeryPoint&gt; for &amp;'a Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'b&gt; Mul&lt;&amp;'b Scalar&gt; for EdwardsPoint","synthetic":false,"types":[]},{"text":"impl&lt;'a&gt; Mul&lt;Scalar&gt; for &amp;'a EdwardsPoint","synthetic":false,"types":[]},{"text":"impl Mul&lt;Scalar&gt; for EdwardsPoint","synthetic":false,"types":[]},{"text":"impl&lt;'b&gt; Mul&lt;&amp;'b EdwardsPoint&gt; for Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'a&gt; Mul&lt;EdwardsPoint&gt; for &amp;'a Scalar","synthetic":false,"types":[]},{"text":"impl Mul&lt;EdwardsPoint&gt; for Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'a, 'b&gt; Mul&lt;&amp;'b Scalar&gt; for &amp;'a EdwardsPoint","synthetic":false,"types":[]},{"text":"impl&lt;'a, 'b&gt; Mul&lt;&amp;'b EdwardsPoint&gt; for &amp;'a Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'a, 'b&gt; Mul&lt;&amp;'b Scalar&gt; for &amp;'a EdwardsBasepointTable","synthetic":false,"types":[]},{"text":"impl&lt;'a, 'b&gt; Mul&lt;&amp;'a EdwardsBasepointTable&gt; for &amp;'b Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'a, 'b&gt; Mul&lt;&amp;'b Scalar&gt; for &amp;'a RistrettoPoint","synthetic":false,"types":[]},{"text":"impl&lt;'a, 'b&gt; Mul&lt;&amp;'b RistrettoPoint&gt; for &amp;'a Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'b&gt; Mul&lt;&amp;'b Scalar&gt; for RistrettoPoint","synthetic":false,"types":[]},{"text":"impl&lt;'a&gt; Mul&lt;Scalar&gt; for &amp;'a RistrettoPoint","synthetic":false,"types":[]},{"text":"impl Mul&lt;Scalar&gt; for RistrettoPoint","synthetic":false,"types":[]},{"text":"impl&lt;'b&gt; Mul&lt;&amp;'b RistrettoPoint&gt; for Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'a&gt; Mul&lt;RistrettoPoint&gt; for &amp;'a Scalar","synthetic":false,"types":[]},{"text":"impl Mul&lt;RistrettoPoint&gt; for Scalar","synthetic":false,"types":[]},{"text":"impl&lt;'a, 'b&gt; Mul&lt;&amp;'b Scalar&gt; for &amp;'a RistrettoBasepointTable","synthetic":false,"types":[]},{"text":"impl&lt;'a, 'b&gt; Mul&lt;&amp;'a RistrettoBasepointTable&gt; for &amp;'b Scalar","synthetic":false,"types":[]}];
implementors["typenum"] = [{"text":"impl&lt;I:&nbsp;Integer&gt; Mul&lt;I&gt; for Z0","synthetic":false,"types":[]},{"text":"impl&lt;U:&nbsp;Unsigned + NonZero&gt; Mul&lt;Z0&gt; for PInt&lt;U&gt;","synthetic":false,"types":[]},{"text":"impl&lt;U:&nbsp;Unsigned + NonZero&gt; Mul&lt;Z0&gt; for NInt&lt;U&gt;","synthetic":false,"types":[]},{"text":"impl&lt;Ul:&nbsp;Unsigned + NonZero, Ur:&nbsp;Unsigned + NonZero&gt; Mul&lt;PInt&lt;Ur&gt;&gt; for PInt&lt;Ul&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: Mul&lt;Ur&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;Ul as Mul&lt;Ur&gt;&gt;::Output: Unsigned + NonZero,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;Ul:&nbsp;Unsigned + NonZero, Ur:&nbsp;Unsigned + NonZero&gt; Mul&lt;NInt&lt;Ur&gt;&gt; for NInt&lt;Ul&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: Mul&lt;Ur&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;Ul as Mul&lt;Ur&gt;&gt;::Output: Unsigned + NonZero,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;Ul:&nbsp;Unsigned + NonZero, Ur:&nbsp;Unsigned + NonZero&gt; Mul&lt;NInt&lt;Ur&gt;&gt; for PInt&lt;Ul&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: Mul&lt;Ur&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;Ul as Mul&lt;Ur&gt;&gt;::Output: Unsigned + NonZero,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;Ul:&nbsp;Unsigned + NonZero, Ur:&nbsp;Unsigned + NonZero&gt; Mul&lt;PInt&lt;Ur&gt;&gt; for NInt&lt;Ul&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: Mul&lt;Ur&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;Ul as Mul&lt;Ur&gt;&gt;::Output: Unsigned + NonZero,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;U:&nbsp;Unsigned, B:&nbsp;Bit&gt; Mul&lt;B0&gt; for UInt&lt;U, B&gt;","synthetic":false,"types":[]},{"text":"impl Mul&lt;B0&gt; for UTerm","synthetic":false,"types":[]},{"text":"impl Mul&lt;B1&gt; for UTerm","synthetic":false,"types":[]},{"text":"impl&lt;U:&nbsp;Unsigned, B:&nbsp;Bit&gt; Mul&lt;B1&gt; for UInt&lt;U, B&gt;","synthetic":false,"types":[]},{"text":"impl&lt;U:&nbsp;Unsigned, B:&nbsp;Bit&gt; Mul&lt;UTerm&gt; for UInt&lt;U, B&gt;","synthetic":false,"types":[]},{"text":"impl&lt;U:&nbsp;Unsigned&gt; Mul&lt;U&gt; for UTerm","synthetic":false,"types":[]},{"text":"impl&lt;Ul:&nbsp;Unsigned, B:&nbsp;Bit, Ur:&nbsp;Unsigned&gt; Mul&lt;UInt&lt;Ur, B&gt;&gt; for UInt&lt;Ul, B0&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: Mul&lt;UInt&lt;Ur, B&gt;&gt;,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;Ul:&nbsp;Unsigned, B:&nbsp;Bit, Ur:&nbsp;Unsigned&gt; Mul&lt;UInt&lt;Ur, B&gt;&gt; for UInt&lt;Ul, B1&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Ul: Mul&lt;UInt&lt;Ur, B&gt;&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;UInt&lt;Prod&lt;Ul, UInt&lt;Ur, B&gt;&gt;, B0&gt;: Add&lt;UInt&lt;Ur, B&gt;&gt;,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;Rhs&gt; Mul&lt;Rhs&gt; for ATerm","synthetic":false,"types":[]},{"text":"impl&lt;V, A, Rhs&gt; Mul&lt;Rhs&gt; for TArr&lt;V, A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;V: Mul&lt;Rhs&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Mul&lt;Rhs&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;Rhs: Copy,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl Mul&lt;ATerm&gt; for Z0","synthetic":false,"types":[]},{"text":"impl&lt;U&gt; Mul&lt;ATerm&gt; for PInt&lt;U&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;U: Unsigned + NonZero,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;U&gt; Mul&lt;ATerm&gt; for NInt&lt;U&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;U: Unsigned + NonZero,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;V, A&gt; Mul&lt;TArr&lt;V, A&gt;&gt; for Z0 <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Z0: Mul&lt;A&gt;,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;V, A, U&gt; Mul&lt;TArr&lt;V, A&gt;&gt; for PInt&lt;U&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;U: Unsigned + NonZero,<br>&nbsp;&nbsp;&nbsp;&nbsp;PInt&lt;U&gt;: Mul&lt;A&gt; + Mul&lt;V&gt;,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;V, A, U&gt; Mul&lt;TArr&lt;V, A&gt;&gt; for NInt&lt;U&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;U: Unsigned + NonZero,<br>&nbsp;&nbsp;&nbsp;&nbsp;NInt&lt;U&gt;: Mul&lt;A&gt; + Mul&lt;V&gt;,&nbsp;</span>","synthetic":false,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()