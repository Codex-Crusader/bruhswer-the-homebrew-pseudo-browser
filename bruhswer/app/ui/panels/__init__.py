"""One module per panel.

Each module here renders the output of exactly one guard. None of them decides
anything: no panel calls SecurityVerifier, no panel gates a launch, no panel touches a
session. They take a frame and some already-computed state and draw it.

That split is not tidiness. A panel that recomputed a verdict could disagree with the
verifier, and then the window would be showing the user a second opinion nobody
measured - the exact defect class this project treats as a vulnerability. So the
rendering lives here and the deciding stays in app/security/.
"""
