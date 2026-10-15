jQuery(function($){
  function post(action, data){
    return $.post(HCYB.ajax, Object.assign({action: action, nonce: HCYB.nonce}, data || {}));
  }
  function setStatus(msg, ok=true){
    $('#hcyb-status').html(ok ? ('✅ ' + msg) : ('❌ ' + msg));
  }

  $(document).on('click', '.hcyb-set-profile', function(e){
    e.preventDefault();
    const id = $(this).data('profile');
    post('hcyb_export_config', {}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd.', false); return; }
      const cfg = res.data.config;
      cfg.profile_active = id;
      post('hcyb_import_config', {json: JSON.stringify(cfg)}).done(function(r2){
        if(!r2.success){ setStatus(r2.data?.message || 'Błąd.', false); return; }
        location.reload();
      });
    });
  });

  $(document).on('click', '.hcyb-save', function(e){
    e.preventDefault();
    const data = {
      waf_enabled: $('#hcyb_waf_enabled').is(':checked') ? 1 : 0,
      waf_mode: $('#hcyb_waf_mode').val(),
      waf_level: $('#hcyb_waf_level').val(),
      waf_fingerprint: $('#hcyb_waf_fingerprint').is(':checked') ? 1 : 0,
      allow_uploads: $('#hcyb_allow_uploads').is(':checked') ? 1 : 0,
      paths_allow: $('#hcyb_paths_allow').val(),
      ip_allow: $('#hcyb_ip_allow').val(),
      ip_deny: $('#hcyb_ip_deny').val(),

      rl_wp_login_enabled: $('#hcyb_rl_wp_login_enabled').is(':checked') ? 1 : 0,
      rl_wp_login_max: $('#hcyb_rl_wp_login_max').val(),
      rl_wp_login_window: $('#hcyb_rl_wp_login_window').val(),
      rl_wp_login_lock: $('#hcyb_rl_wp_login_lock').val(),
      rl_wp_login_methods: $('#hcyb_rl_wp_login_methods').val(),

      rl_xmlrpc_enabled: $('#hcyb_rl_xmlrpc_enabled').is(':checked') ? 1 : 0,
      rl_xmlrpc_max: $('#hcyb_rl_xmlrpc_max').val(),
      rl_xmlrpc_window: $('#hcyb_rl_xmlrpc_window').val(),
      rl_xmlrpc_lock: $('#hcyb_rl_xmlrpc_lock').val(),
      rl_xmlrpc_methods: $('#hcyb_rl_xmlrpc_methods').val(),

      rl_rest_enabled: $('#hcyb_rl_rest_enabled').is(':checked') ? 1 : 0,
      rl_rest_max: $('#hcyb_rl_rest_max').val(),
      rl_rest_window: $('#hcyb_rl_rest_window').val(),
      rl_rest_lock: $('#hcyb_rl_rest_lock').val(),
      rl_rest_methods: $('#hcyb_rl_rest_methods').val(),

      rl_admin_ajax_enabled: $('#hcyb_rl_admin_ajax_enabled').is(':checked') ? 1 : 0,
      rl_admin_ajax_max: $('#hcyb_rl_admin_ajax_max').val(),
      rl_admin_ajax_window: $('#hcyb_rl_admin_ajax_window').val(),
      rl_admin_ajax_lock: $('#hcyb_rl_admin_ajax_lock').val(),
      rl_admin_ajax_methods: $('#hcyb_rl_admin_ajax_methods').val(),
      xmlrpc: $('#hcyb_xmlrpc').val(),
      rest_users: $('#hcyb_rest_users').is(':checked') ? 1 : 0,
      author_enum: $('#hcyb_author_enum').is(':checked') ? 1 : 0,
      file_edit: $('#hcyb_file_edit').is(':checked') ? 1 : 0,
      headers_enabled: $('#hcyb_headers_enabled').is(':checked') ? 1 : 0,
      headers_hsts: $('#hcyb_headers_hsts').is(':checked') ? 1 : 0,
      headers_csp: $('#hcyb_headers_csp').val(),
      hosts: $('#hcyb_hosts').val(),
      iprep_enabled: $('#hcyb_iprep_enabled').is(':checked') ? 1 : 0,
      iprep_provider: $('#hcyb_iprep_provider').val(),
      iprep_ttl: $('#hcyb_iprep_ttl').val(),
      iprep_block_threshold: $('#hcyb_iprep_block_threshold').val(),

      adaptive_enabled: $('#hcyb_adaptive_enabled').is(':checked') ? 1 : 0,
      adaptive_window: $('#hcyb_adaptive_window').val(),
      adaptive_threshold: $('#hcyb_adaptive_threshold').val(),
      adaptive_duration: $('#hcyb_adaptive_duration').val()
    };
    post('hcyb_save_settings', data).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd zapisu.', false); return; }
      setStatus(res.data.message || 'Zapisano.');
    });
  });

  $(document).on('click', '.hcyb-baseline', function(e){
    e.preventDefault();
    setStatus('Tworzę baseline...', true);
    post('hcyb_scan_baseline', {}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd baseline.', false); return; }
      setStatus(res.data.message || 'Baseline OK.');
    });
  });

  $(document).on('click', '.hcyb-scan-quick', function(e){
    e.preventDefault();
    setStatus('Skanuję...', true);
    post('hcyb_scan_quick', {}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd skanu.', false); return; }
      setStatus(res.data.message || 'Skan OK.');
    });
  });

  $(document).on('click', '.hcyb-export', function(e){
    e.preventDefault();
    post('hcyb_export_config', {}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd eksportu.', false); return; }
      const json = JSON.stringify(res.data.config, null, 2);
      const ta = $('<textarea class="large-text code" rows="12"></textarea>').val(json);
      $('#hcyb-status').html('').append(ta);
    });
  });

  $(document).on('click', '.hcyb-import', function(e){
    e.preventDefault();
    const json = $('#hcyb-import-json').val();
    post('hcyb_import_config', {json: json}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd importu.', false); return; }
      setStatus(res.data.message || 'Zaimportowano.');
      setTimeout(()=>location.reload(), 700);
    });
  });

  // Polityki: eksport/import podpisany
  $(document).on('click', '.hcyb-policy-export-signed', function(e){
    e.preventDefault();
    post('hcyb_policy_export_signed', {}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd eksportu.', false); return; }
      const payloadJson = JSON.stringify(res.data.payload, null, 2);
      const sig = res.data.sig;
      const ta = $('<textarea class="large-text code" rows="10"></textarea>').val(payloadJson);
      const inp = $('<input type="text" class="large-text code" />').val(sig);
      const box = $('<div></div>');
      box.append('<p><strong>Payload (JSON):</strong></p>').append(ta);
      box.append('<p><strong>Podpis (sig):</strong></p>').append(inp);
      $('#hcyb-status').html('').append(box);
    });
  });

  $(document).on('click', '.hcyb-policy-import-signed', function(e){
    e.preventDefault();
    const json = $('#hcyb-import-signed-json').val();
    const sig = $('#hcyb-import-signed-sig').val();
    post('hcyb_policy_import_signed', {json: json, sig: sig}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd importu.', false); return; }
      setStatus(res.data.message || 'Zaimportowano podpisaną politykę.');
      setTimeout(()=>location.reload(), 700);
    });
  });

  function renderVersions(list){
    const box = $('#hcyb-policy-versions');
    if(!box.length) return;
    box.empty();
    if(!list || !list.length){ box.append('<p class="hcyb-muted">Brak snapshotów.</p>'); return; }
    const t = $('<table class="widefat striped"></table>');
    t.append('<thead><tr><th>ID</th><th>Data (UTC)</th><th>Powód</th><th>Źródło</th><th>Akcje</th></tr></thead>');
    const tb = $('<tbody></tbody>');
    list.forEach(function(v){
      const tr = $('<tr></tr>');
      tr.append('<td><code>' + v.id + '</code></td>');
      tr.append('<td>' + (v.created_at||'') + '</td>');
      tr.append('<td>' + (v.reason||'') + '</td>');
      tr.append('<td><code>' + (v.source||'') + '</code></td>');
      const btnDiff = $('<button class="button">Diff</button>').addClass('hcyb-policy-diff').attr('data-id', v.id);
      const btnRb = $('<button class="button button-secondary">Rollback</button>').addClass('hcyb-policy-rollback').attr('data-id', v.id);
      const td = $('<td></td>').append(btnDiff).append(' ').append(btnRb);
      tr.append(td);
      tb.append(tr);
    });
    t.append(tb);
    box.append(t);
    box.append('<div id="hcyb-policy-diff-box" style="margin-top:12px;"></div>');
  }

  function refreshVersions(){
    post('hcyb_policy_list_versions', {}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd listy wersji.', false); return; }
      renderVersions(res.data.versions);
    });
  }

  $(document).on('click', '.hcyb-policy-refresh', function(e){
    e.preventDefault();
    refreshVersions();
  });

  $(document).on('click', '.hcyb-policy-diff', function(e){
    e.preventDefault();
    const id = $(this).data('id');
    const box = $('#hcyb-policy-diff-box');
    box.html('<p class="hcyb-muted">Liczymy diff...</p>');
    post('hcyb_policy_diff', {id: id}).done(function(res){
      if(!res.success){ box.html('<p class="hcyb-muted">Błąd diff.</p>'); return; }
      const changes = res.data.changes || [];
      let html = '<h3>Diff (zmian: ' + (res.data.count||0) + ')</h3>';
      html += '<table class="widefat striped"><thead><tr><th>Ścieżka</th><th>Stare</th><th>Nowe</th></tr></thead><tbody>';
      changes.forEach(function(c){
        html += '<tr><td><code>' + c.path + '</code></td><td><pre style="white-space:pre-wrap;">' + (JSON.stringify(c.old)) + '</pre></td><td><pre style="white-space:pre-wrap;">' + (JSON.stringify(c.new)) + '</pre></td></tr>';
      });
      html += '</tbody></table>';
      if((res.data.count||0) > changes.length){
        html += '<p class="hcyb-muted">Pokazano pierwsze ' + changes.length + ' zmian.</p>';
      }
      box.html(html);
    });
  });

  $(document).on('click', '.hcyb-policy-rollback', function(e){
    e.preventDefault();
    const id = $(this).data('id');
    if(!confirm('Przywrócić politykę z wersji #' + id + '?')) return;
    post('hcyb_policy_rollback', {id: id}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Rollback nieudany.', false); return; }
      setStatus(res.data.message || 'Przywrócono.');
      setTimeout(()=>location.reload(), 700);
    });
  });

  // auto-refresh gdy jesteśmy na Politykach
  if($('#hcyb-policy-versions').length){
    refreshVersions();
  }

  $(document).on('click', '.hcyb-generate-mu', function(e){
    e.preventDefault();
    post('hcyb_generate_mu_loader', {}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd.', false); return; }
      setStatus(res.data.message || 'Wygenerowano MU-loader.');
    });
  });
  $(document).on('click', '.hcyb-surface-scan', function(e){
    e.preventDefault();
    setStatus('Skanuję ekspozycję...', true);
    post('hcyb_surface_scan', {}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd skanu.', false); return; }
      setStatus(res.data.message || 'Skan zakończony.');
      const data = res.data.data;
      const box = $('#hcyb-surface-results');
      box.empty();
      if(!data || !data.results){ box.append('<p class="hcyb-muted">Brak danych.</p>'); return; }
      data.results.forEach(function(site){
        const sum = site.summary || {};
        const head = $('<h2></h2>').text('Host: ' + site.host + ' (HIGH ' + (sum.high||0) + ', MED ' + (sum.med||0) + ', LOW ' + (sum.low||0) + ')');
        box.append(head);
        if(site.headers && site.headers.ok){
          const miss = (site.headers.missing||[]).join(', ');
          const p = $('<p class="hcyb-muted"></p>').text('Nagłówki: brakujące: ' + (miss || '—'));
          box.append(p);
        } else if(site.headers && site.headers.note){
          box.append('<p class="hcyb-muted">' + site.headers.note + '</p>');
        }
        const t = $('<table class="widefat striped"></table>');
        t.append('<thead><tr><th>Ryzyko</th><th>Test</th><th>Ścieżka</th><th>Status</th><th>Opis</th></tr></thead>');
        const tb = $('<tbody></tbody>');
        (site.items||[]).forEach(function(it){
          const r = it.risk_effective || 'info';
          const badge = '<span class="hcyb-badge hcyb-badge-' + r + '">' + r.toUpperCase() + '</span>';
          const row = $('<tr></tr>');
          row.append('<td>' + badge + '</td>');
          row.append('<td><code>' + (it.id||'') + '</code></td>');
          row.append('<td><code>' + (it.path||'') + '</code></td>');
          row.append('<td>' + (it.status||'') + '</td>');
          row.append('<td>' + (it.note||'') + '</td>');
          tb.append(row);
        });
        t.append(tb);
        box.append(t);
      });
    });
  });



  // Reputacja IP
  window.HCYB = window.HCYB || {};

  window.HCYB.checkIP = function(){
    const ip = $('#hcyb_ip_input').val().trim();
    if(!ip){ $('#hcyb_ip_status').text('Podaj IP.'); return; }
    $('#hcyb_ip_status').text('Sprawdzam...');
    $('#hcyb_ip_result').hide().text('');
    post('hcyb_check_ip', {ip: ip}).done(function(res){
      if(res && res.success){
        $('#hcyb_ip_status').text('OK');
        $('#hcyb_ip_result').text(JSON.stringify(res.data.record, null, 2)).show();
      } else {
        $('#hcyb_ip_status').text('Błąd');
      }
    }).fail(function(){
      $('#hcyb_ip_status').text('Błąd');
    });
  };

  window.HCYB.saveReputationSettings = function(){
    const enabled = $('#hcyb_rep_enabled').is(':checked') ? 1 : 0;
    const thr = parseInt($('#hcyb_rep_threshold').val(), 10);
    post('hcyb_save_reputation', {enabled: enabled, block_threshold: isNaN(thr) ? 80 : thr}).done(function(res){
      const msg = (res && res.data && res.data.message) ? res.data.message : (res && res.success ? 'Zapisano.' : 'Błąd zapisu');
      $('#hcyb_ip_status').text(msg);
    }).fail(function(){
      $('#hcyb_ip_status').text('Błąd zapisu');
    });
  };


  // Pełny skan (batch)
  let fullscanTimer = null;

  function renderFullscanProgress(st){
    const box = $('#hcyb-fullscan-progress');
    if(!box.length) return;
    const bar = box.find('.hcyb-progress__bar');
    const total = parseInt(st.total||0,10);
    const offset = parseInt(st.offset||0,10);
    if(total>0){
      const pct = Math.max(0, Math.min(100, Math.round((offset/total)*100)));
      box.show();
      bar.css('width', pct + '%');
    }
  }

  function tickFullscan(){
    post('hcyb_fullscan_tick', {}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd tick.', false); stopFullscanTimer(); return; }
      const r = res.data.result || {};
      const st = r.status || {};
      renderFullscanProgress(st);
      if(r.done){
        setStatus('Pełny skan zakończony. Sprawdź logi skanera.', true);
        stopFullscanTimer();
        return;
      }
      // delikatny status
      const msg = 'Pełny skan: ' + (st.offset||0) + '/' + (st.total||0) + ' | tick: sprawdzono ' + (r.checked||0) + ', zmiany ' + (r.changed||0) + ', brak ' + (r.missing||0) + ', podejrzane ' + (r.suspicious||0);
      $('#hcyb-status').text(msg);
      // kolejny tick
      fullscanTimer = setTimeout(tickFullscan, 900);
    }).fail(function(){
      setStatus('Błąd tick (sieć).', false);
      stopFullscanTimer();
    });
  }

  function stopFullscanTimer(){
    if(fullscanTimer){ clearTimeout(fullscanTimer); fullscanTimer=null; }
  }

  $(document).on('click', '.hcyb-fullscan-start', function(e){
    e.preventDefault();
    stopFullscanTimer();
    setStatus('Uruchamiam pełny skan (batch)...', true);
    post('hcyb_fullscan_start', {limit: 250}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd startu.', false); return; }
      const st = res.data.status || {};
      renderFullscanProgress({offset:0,total:st.total||0});
      setStatus('Pełny skan uruchomiony. Startuję batch...', true);
      fullscanTimer = setTimeout(tickFullscan, 500);
    });
  });

  $(document).on('click', '.hcyb-fullscan-stop', function(e){
    e.preventDefault();
    stopFullscanTimer();
    post('hcyb_fullscan_stop', {}).done(function(res){
      setStatus(res.data?.message || 'Zatrzymano.', true);
    });
  });

  // Tryb kryzysowy
  $(document).on('click', '.hcyb-emergency-enable', function(e){
    e.preventDefault();
    const minutes = parseInt($(this).data('minutes') || 60, 10);
    setStatus('Włączam tryb kryzysowy...', true);
    post('hcyb_emergency_enable', {minutes: minutes}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd.', false); return; }
      setStatus('Tryb kryzysowy włączony.', true);
      setTimeout(()=>location.reload(), 600);
    });
  });

  $(document).on('click', '.hcyb-emergency-disable', function(e){
    e.preventDefault();
    setStatus('Wyłączam tryb kryzysowy...', true);
    post('hcyb_emergency_disable', {}).done(function(res){
      if(!res.success){ setStatus(res.data?.message || 'Błąd.', false); return; }
      setStatus('Tryb kryzysowy wyłączony.', true);
      setTimeout(()=>location.reload(), 600);
    });
  });

});
