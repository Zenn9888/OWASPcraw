// mongo --quiet < mongo_fix_external_id.js
(function(){
  const dbName = 'webcommentIT';
  const collName = 'comment';
  const uniqEid = 'uniq_source_eid';
  const uniqPid = 'uniq_source_pid';

  const dbx = db.getSiblingDB(dbName);
  const c = dbx.getCollection(collName);

  print(`[fix] DB=${dbName} Coll=${collName}`);

  // 1) Show index summary
  const idx = c.getIndexes().map(i => i.name);
  print('[fix] indexes before = ' + JSON.stringify(idx));

  // 2) Backfill: set external_id = platform_id when null/missing
  const filter = {$or:[{external_id: null}, {external_id: {$exists: false}}]};
  const candidates = c.countDocuments(filter);
  print(`[fix] docs needing external_id backfill = ${candidates}`);
  if (candidates > 0) {
    const res = c.updateMany(filter, [{$set: {external_id: "$platform_id"}}]);
    print('[fix] backfill modified = ' + res.modifiedCount);
  }

  // 3) Ensure unique index on (source, platform_id)
  const hasPid = idx.includes(uniqPid);
  if (!hasPid) {
    print('[fix] creating unique index on (source, platform_id) ...');
    c.createIndex({source:1, platform_id:1}, {unique:true, name:uniqPid});
  } else {
    print('[fix] OK: unique (source, platform_id) exists');
  }

  // 4) Drop legacy unique (source, external_id) to avoid future null collisions
  if (idx.includes(uniqEid)) {
    try {
      print('[fix] dropping legacy unique index ' + uniqEid + ' ...');
      c.dropIndex(uniqEid);
      print('[fix] dropped ' + uniqEid);
    } catch(e) {
      print('[fix] dropIndex error: ' + e);
    }
  } else {
    print('[fix] no legacy index ' + uniqEid);
  }

  // 5) (Optional) Recreate non-unique helper index on (source, external_id) for lookups
  print('[fix] creating non-unique helper index on (source, external_id) ...');
  try {
    c.createIndex({source:1, external_id:1}, {name:'idx_source_eid'});
  } catch(e) {
    print('[fix] create helper idx error: ' + e);
  }

  const idxAfter = c.getIndexes().map(i => i.name);
  print('[fix] indexes after  = ' + JSON.stringify(idxAfter));
  print('[fix] done.');
})();