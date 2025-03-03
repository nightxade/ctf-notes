# ctf-notes
repo to store ctf notes
# Rules
1. If a **mitigation** is in the tags of a note, that means it is **related** to the attack. The mitigation may have been implemented to weaken/eliminate this attack, or the attack may have been created to deal with the mitigation.
2. The **GLIBC version** in which a technique was patched is included in the **tags** of a note, where **hyphens** replace the periods in the version number.
# Tags
```dataviewjs
dv.table(["Tag"], Array.from(new Set(dv.pages('"ctf-notes"').file.tags))
	.sort()
	.map(t => [t, dv.pages(t + ' and "ctf-notes"').map(p => p.file.link)]))
```
