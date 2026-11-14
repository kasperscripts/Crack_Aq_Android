from pathlib import Path
root=Path(__file__).parent
p=root/'ui-smali/dev/phantom/i/u.smali';text=p.read_text()
needle='    invoke-virtual {v0}, Ldev/phantom/i/d0;->K()V'
assert text.count(needle)==1
text=text.replace(needle,needle+'''

    iget-boolean v1, v0, Ldev/phantom/i/d0;->J:Z
    if-nez v1, :icon_reveal_done
    iget-boolean v1, v0, Ldev/phantom/i/d0;->I:Z
    if-nez v1, :icon_reveal_done
    invoke-virtual {v0}, Ldev/phantom/i/d0;->Q()V
    :icon_reveal_done''')
p.write_text(text)
p=root/'ui-smali/dev/phantom/i/g.smali';text=p.read_text();needle='    sget-object v0, Ldev/phantom/i/d0;->i0:[Ljava/lang/String;'
assert text.count(needle)==1
text=text.replace(needle,'''    sget-object v0, Ldev/secret/oxide/internal/InternalUI;->c:Ldev/phantom/i/d0;
    if-eqz v0, :icon_counter_done
    iget-boolean v1, v0, Ldev/phantom/i/d0;->J:Z
    if-nez v1, :icon_counter_done
    invoke-virtual {v0}, Ldev/phantom/i/d0;->Q()V
    :icon_counter_done''')
p.write_text(text)
print('Menu opens once after initial placement; counter tap also opens/closes panel.')
