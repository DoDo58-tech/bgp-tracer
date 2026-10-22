#!/usr/bin/env python3
import glob
import re

# Step 1: Extract citations in order
citations = []
for f in sorted(glob.glob('section*.tex')):
    with open(f, 'r') as fp:
        content = fp.read()
    for match in re.findall(r'\\cite\{([^}]+)\}', content):
        for c in match.split(','):
            c = c.strip()
            if c and c not in citations:
                citations.append(c)

print(f'Found {len(citations)} unique citations')

# Step 2: Parse bbl using string methods
with open('main.bbl', 'r') as f:
    bbl = f.read()

# Find all bibitems - format is \bibitem[NUM]%\n{KEY}
bibitems = {}
pos = 0
while True:
    idx = bbl.find('\\bibitem[', pos)
    if idx == -1:
        break
    
    # Find the closing bracket and percent sign
    bracket_end = bbl.find(']', idx)
    if bracket_end == -1:
        break
    
    # Extract the sequential number
    num_start = idx + len('\\bibitem[')
    seq_num = bbl[num_start:bracket_end]
    
    # Find the key in the next {KEY}
    key_start = bbl.find('{', bracket_end) + 1
    key_end = bbl.find('}', key_start)
    key = bbl[key_start:key_end]
    
    # Find end of this entry (next \bibitem or \end)
    rest = bbl[key_end:]
    next_idx = rest.find('\\bibitem[')
    end_idx = rest.find('\\end{thebibliography}')
    
    if end_idx != -1 and (next_idx == -1 or end_idx < next_idx):
        entry_end = key_end + end_idx
    elif next_idx != -1:
        entry_end = key_end + next_idx
    else:
        entry_end = len(bbl)
    
    bibitems[key] = (seq_num, bbl[idx:entry_end])
    pos = entry_end

print(f'Found {len(bibitems)} bibitems')

# Step 3: Build new bbl
header_end = bbl.find('\\bibitem[')
header = bbl[:header_end]
# Fix counter
old_num = re.search(r'\\begin\{thebibliography\}\{([^}]+)\}', header)
if old_num:
    header = header.replace(
        f'\\begin{{thebibliography}}{{{old_num.group(1)}}}',
        f'\\begin{{thebibliography}}{{{len(citations)}}}'
    )

footer = '\\end{thebibliography}'

with open('main.bbl', 'w') as f:
    f.write(header)
    written = 0
    for i, key in enumerate(citations, 1):
        if key in bibitems:
            _, entry = bibitems[key]
            # Replace old number with new sequential number
            entry = entry.replace(f'\\bibitem[{bibitems[key][0]}]%', f'\\bibitem[{i}]%')
            f.write(entry + '\n')
            written += 1
    # Write unused entries
    for key, (_, entry) in bibitems.items():
        if key not in citations:
            f.write(entry + '\n')
    f.write(footer)

print(f'Wrote {written} entries with sequential numbers')

# Verify
with open('main.bbl', 'r') as f:
    content = f.read()
count = content.count('\\bibitem[')
print(f'Verification: {count} bibitem entries')

# Print first 10
print('\nFirst 10 bibitems:')
for i, key in enumerate(citations[:10], 1):
    if key in bibitems:
        print(f'  [{i}] {key}')
