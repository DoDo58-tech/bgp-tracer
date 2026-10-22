#!/bin/bash
# Build script for CoNEXT paper with sequential citation ordering
cd /data/bgp_tracer/docs/paper

# Step 1: Clean old files
rm -f *.bbl *.aux

# Step 2: First tectonic compile (generates bbl)
echo "Running tectonic (first pass)..."
tectonic main.tex --keep-intermediates 2>/dev/null

# Step 3: Reorder bbl by citation order
echo "Reordering bibliography..."
python3 reorder_bbl.py

# Step 4: Second tectonic compile (uses reordered bbl)
echo "Running tectonic (second pass)..."
tectonic main.tex 2>/dev/null

echo "Done! main.pdf generated with sequential citations."
