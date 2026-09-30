import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath("_deck_tools")))
from wrapmeasure import wrapped_lines, text_width
cands = {
 "v1": "Multi-core pipeline built for horizontal scale-out: receiver/splitter \u2192 N workers \u2192 destination aggregators. 120,000 flows/sec: target, hardware validation in progress \u2014 not measured.",
 "v2": "Multi-core pipeline built: receiver/splitter \u2192 N detection workers \u2192 destination aggregators. 120,000 flows/sec: target, validation in progress, not measured.",
 "v3": "Multi-core pipeline built: receiver/splitter \u2192 N workers \u2192 destination aggregators. 120,000 flows/sec is a target, hardware validation in progress \u2014 not measured.",
 "v4": "Multi-core pipeline built for scale-out: receiver/splitter \u2192 N workers \u2192 destination aggregators. 120,000 flows/sec is a target, validation in progress \u2014 not measured.",
 "v5": "Multi-core pipeline built: receiver/splitter \u2192 N detection workers \u2192 destination aggregators. 120,000 flows/sec is a target, hardware validation in progress.",
}
for k,v in cands.items():
    n = len(wrapped_lines(v, 8.5, 289.5))
    print(k, "chars", len(v), "lines", n)
    for i,ln in enumerate(wrapped_lines(v,8.5,289.5),1):
        print("    L%d %6.1f %s" % (i, text_width(ln,8.5), ln))
