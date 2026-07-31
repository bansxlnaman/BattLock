function frames = export_frames(outdir)
%EXPORT_FRAMES  Run Battlock_System2 across all attack modes and write the
%   CAN frame stream to CSV.
%
%   The frame fields (per logged signal) are:
%       signature  <- Attack_Module SIGNATURE output
%       counter    <- Attack_Module rx_counter output
%       voltage    <- Attack_Module rx_voltage output
%       nonce      <- Vehicle_Node NONCE output
%   Plus the model's own verdict signals for cross-checking:
%       model_state, model_auth, model_replay, model_injection, model_soc
%
%   Writes <outdir>\frames.csv with columns:
%       mode,time,nonce,signature,counter,voltage, ...
%       model_state,model_auth,model_replay,model_injection,model_soc

    if nargin < 1
        outdir = pwd;
    end

    mdl = 'Battlock_System2';
    addpath(fileparts(mfilename('fullpath')));

    load_system(mdl);
    cleanup = onCleanup(@() close_system(mdl, 0));

    % Ensure logging is on for the signals we need.
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
        out(mode+1).nonce   = getv('AUTH_RESULT_2');   % Vehicle NONCE
        out(mode+1).sig     = getv('SIGNATURE_1');     % transmitted signature
        out(mode+1).counter = getv('SIGNATURE_2');     % transmitted counter
        out(mode+1).volt    = getv('SIGNATURE_3');     % transmitted voltage
        out(mode+1).state   = getv('state_1');
        out(mode+1).auth    = getv('AUTH_RESULT_1');
        out(mode+1).replay  = getv('replay_detected_1');
        out(mode+1).inj     = getv('injection_detected_1');
        out(mode+1).soc     = getv('gated_soc_1');
        fprintf('export mode=%d done\n', mode);
    end

    % Reset to baseline.
    set_param(atkBlk, 'Value', '0');

    % ------------------------------------------------------------------
    % Assemble frame rows. Use the telemetry cadence (counter clock) as
    % the CAN message clock, and interpolate the other fields to it.
    % ------------------------------------------------------------------
    % Interpolate a signal trace onto a target time grid, handling
    % single-sample (constant) traces gracefully.
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
        % sample time grid for frames (where counter changes) + endpoints
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
