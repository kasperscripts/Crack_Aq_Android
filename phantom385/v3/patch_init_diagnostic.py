from pathlib import Path
root=Path(__file__).parent
p=root/'ui-smali/dev/phantom/i/h.smali';s=p.read_text()
start=s.index('    :goto_198\n');end=s.index('    :cond_1a4\n',start)
part=s[start:end];needle='    invoke-virtual {v1, v0}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V'
assert part.count(needle)==1
part=part.replace(needle,'''    const-string v2, "\\n"
    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    iget-object v2, p0, Ldev/phantom/i/h;->b:Ljava/lang/Object;
    check-cast v2, Ljava/lang/String;
    invoke-virtual {v2}, Ljava/lang/String;->length()I
    move-result v3
    const/16 v4, 0x180
    invoke-static {v3, v4}, Ljava/lang/Math;->min(II)I
    move-result v3
    const/4 v4, 0x0
    invoke-virtual {v2, v4, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;
    move-result-object v2
    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
'''+needle)
s=s[:start]+part+s[end:];p.write_text(s)
print('Startup failure screen retains bounded underlying ERROR text.')
