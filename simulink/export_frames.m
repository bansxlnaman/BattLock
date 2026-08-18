function frames = export_frames(outdir)
% EXPORT_FRAMES  Export Simulink frames for attack modes 0-5.
%
% The model (Battlock_System2.slx) currently implements modes 0-5.
% Modes 6-11 are generated separately by generate_extra_modes.py from the
% real BattLock Python attack classes.  run_integration.m combines both
% sources and verifies/plots all 12 modes.

    if nargin < 1
        outdir = pwd;
    end

    mdl = 'Battlock_System2';
    addpath(fileparts(mfilename('fullpath')));

    load_system(mdl);
    cleanup = onCleanup(@() close_system(mdl, 0));

    sysMap = struct( ...
        'Vehicle_Node',        'AUTH_RESULT', ...
        'Attack_Module',       'SIGNATURE', ...
        'State_Machine',       'state', ...
        'Replay_Protection',   'replay_detected', ...
        'Injection_Detection', 'injection_detected', ...
        'Telemetry',           'gated_soc');
    names = fieldnames(sysMap);
    for i = 1:numel(names)
        ph = get_param([mdl '/' names{i}], 'PortHandles');
        for p = 1:numel(ph.Outport)
            set_param(ph.Outport(p), 'DataLogging', 'on');
            set_param(ph.Outport(p), 'DataLoggingName', [sysMap.(names{i}) '_' num2str(p)]);
            set_param(ph.Outport(p), 'DataLoggingNameMode', 'Custom');
        end
    end

    atkBlk = [mdl '/Attack_Module/Constant5'];
    out = struct();
    for mode = 0:5
        set_param(atkBlk, 'Value', num2str(mode));
        r = sim(mdl);
        lo = r.logsout;
        getv = @(nm) lo.getElement(nm).Values;
        out(mode+1).mode = mode;
        out(mode+1).nonce   = getv('AUTH_RESULT_2');
        out(mode+1).sig     = getv('SIGNATURE_1');
        out(mode+1).counter = getv('SIGNATURE_2');
        out(mode+1).volt    = getv('SIGNATURE_3');
        out(mode+1).state   = getv('state_1');
        out(mode+1).auth    = getv('AUTH_RESULT_1');
        out(mode+1).replay  = getv('replay_detected_1');
        out(mode+1).inj     = getv('injection_detected_1');
        out(mode+1).soc     = getv('gated_soc_1');
        fprintf('export mode=%d done\n', mode);
    end

    set_param(atkBlk, 'Value', '0');

    function v = resample_trace(trace, tg)
        td = trace.Time(:);
        vd = double(trace.Data(:));
        if numel(td) < 2
            v = vd(1) * ones(numel(tg), 1);
        else
            v = interp1(td, vd, tg, 'previous', 'extrap');
        end
    end

    rows = [];
    for m = 1:6
        c = out(m).counter;
        cdata = c.Data(:);
        tgrid = c.Time(:);
        ts = unique([tgrid(1); tgrid(2:end)]);
        ts = ts(isfinite(ts));
        sig   = resample_trace(out(m).sig,   ts);
        nonce = resample_trace(out(m).nonce, ts);
        volt  = resample_trace(out(m).volt,  ts);
        cnew  = resample_trace(out(m).counter, ts);
        st    = resample_trace(out(m).state, ts);
        au    = resample_trace(out(m).auth,  ts);
        rp    = resample_trace(out(m).replay,ts);
        inj   = resample_trace(out(m).inj,   ts);
        soc   = resample_trace(out(m).soc,   ts);
        rows  = [rows; [out(m).mode*ones(numel(ts),1), ts, nonce, sig, cnew, volt, st, au, rp, inj, soc]];
    end

    frames = array2table(rows, 'VariableNames', ...
        {'mode','time','nonce','signature','counter','voltage', ...
         'model_state','model_auth','model_replay','model_injection','model_soc'});

    fname = fullfile(outdir, 'frames.csv');
    writetable(frames, fname);
    fprintf('Wrote %d frames to %s\n', height(frames), fname);
end
