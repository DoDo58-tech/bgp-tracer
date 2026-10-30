"""Ground-truth verification helpers.

This package answers one question per event: *is the labelled incident
verifiable in the data we have?*  A ground-truth row may only be used to
score a detector if all three of the following hold:

1. the routing anomaly is visible in the BGP update stream;
2. the traffic of the affected network measurably drops;
3. the drop is attributable to the routing anomaly rather than to an
   unrelated cause.

The third point is the hard one.  Correlation between a routing change
and a traffic drop does not establish causation on its own, so the
verification compares the drop against the *control* series of a network
that was not affected -- if the affected network's drop is not visible in
the control, the drop is specific to the routing event.
"""
