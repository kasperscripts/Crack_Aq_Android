from pathlib import Path
root=Path(__file__).parent
p=root/'outer-smali/dev/secret/oxide/MainActivity.smali';s=p.read_text();needle='    invoke-super {p0}, Landroid/app/Activity;->onResume()V'
assert s.count(needle)==1
s=s.replace(needle,needle+'''

    :icon_refresh_start
    iget v0, p0, Ldev/secret/oxide/MainActivity;->l:I
    const/4 v1, 0x1
    if-ne v0, v1, :icon_refresh_done
    iget-boolean v0, p0, Ldev/secret/oxide/MainActivity;->m:Z
    if-nez v0, :icon_refresh_done
    invoke-static {p0}, Ldev/icon/RuntimeAsset;->needsLuluRefresh(Landroid/content/Context;)Z
    move-result v0
    if-eqz v0, :icon_refresh_done
    invoke-virtual {p0}, Ldev/secret/oxide/MainActivity;->h()V
    :icon_refresh_end
    goto :icon_refresh_done
    .catch Ljava/lang/Exception; {:icon_refresh_start .. :icon_refresh_end} :icon_refresh_failed
    :icon_refresh_failed
    move-exception v0
    :icon_refresh_done''')
p.write_text(s)
p=root/'ui-smali/dev/phantom/i/h.smali';s=p.read_text();start=s.index('    :goto_198\n');end=s.index('    :cond_1a4\n',start)
s=s[:start]+'''
    :goto_198
    sget-object v1, Ldev/secret/oxide/internal/BootstrapUI;->g:Landroid/widget/TextView;
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
    const-string v3, "ICON4: "
    invoke-virtual {v3, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    const-string v3, "\\n"
    invoke-virtual {v2, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    invoke-virtual {v2, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    const/4 v2, 0x0
    invoke-virtual {v1, v2}, Landroid/widget/TextView;->setSingleLine(Z)V
    const/16 v2, 0x10
    invoke-virtual {v1, v2}, Landroid/widget/TextView;->setMaxLines(I)V
    invoke-virtual {v1, v0}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
    goto :goto_1c3

'''+s[end:]
p.write_text(s)
print('Existing Lulu runtime refresh added; underlying startup error shown first.')
