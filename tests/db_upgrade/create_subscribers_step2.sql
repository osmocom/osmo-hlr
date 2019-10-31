update subscriber set vlr_number = 'MSC-1' where id = 1;
update subscriber set ms_purged_cs = 1 where id = 2;
update subscriber set ms_purged_ps = 1 where id = 3;
update subscriber set nam_cs = 0 where id = 4;
update subscriber set nam_ps = 0 where id = 5;
update subscriber set nam_cs = 0, nam_ps = 0 where id = 6;
