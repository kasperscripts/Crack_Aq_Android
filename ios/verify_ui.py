from fixture_image import *
from unicorn import UC_HOOK_CODE

for pressed in [False,True]:
    m,view,b=initialized(True);draws=[]
    def ui(u,pc,size,data):
        if pc==BASE+0x5e964:
            draws.append(('section',m.cstr(m.reg(0)).decode()));m.ret(77)
        elif pc==BASE+0x1bc6f0:
            draws.append(('button',m.cstr(m.reg(0)).decode()))
            assert bytes(u.mem_read(m.reg(1),8))==bytes(8)
            m.ret(int(pressed))
    h=m.u.hook_add(UC_HOOK_CODE,ui)
    title=m.malloc(64);m.u.mem_write(title,b'Telegram: @Icon_Crack\0')
    result=m.call(0x3e7500,title,0)
    assert result==77 and draws==[('section','Telegram: @Icon_Crack'),('button','Telegram: @Icon_Crack')]
    assert len(m.queued)==int(pressed)
    if pressed:
        block=m.queued[0][1];m.call(0x3e7640,block)
        assert m.opened_urls==['https://t.me/Icon_Crack']
    else:assert not getattr(m,'opened_urls',[])
    m.u.hook_del(h)
report={'telegram_button_target':'https://t.me/Icon_Crack','opens_only_when_pressed':True,'opening_dispatched_to_main_queue':True,'original_section_drawing_preserved':True,'device_ui_rendering_tested':False}
(d.root/'ui-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print('Telegram button: idle, click, main queue and URL verified')
