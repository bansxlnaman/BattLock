function verify_battlock()

    mdl = 'Battlock_System2';
    addpath(fileparts(mfilename('fullpath')));

    load_system(mdl);
    cleanup = onCleanup(@() close_system(mdl, 0));

    sysMap = struct( ...
        'State_Machine',        'state', ...
        'Vehicle_Node',         'AUTH_RESULT', ...
        'Telemetry',            'gated_soc', ...
        'Replay_Protection',    'replay_detected', ...
        'Injection_Detection',  'injection_detected', ...
        'Attack_Module',        'SIGNATURE');
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
    descriptions = { ...
        'No attack (baseline)', ...
        'Replay attack', ...
        'Signature spoofing', ...
        'Voltage injection', ...
        'Signature dropping', ...
        'Spoof + voltage injection'};

    results = struct();
    for mode = 0:5
        set_param(atkBlk, 'Value', num2str(mode));
        out = sim(mdl);
        lo = out.logsout;
        getv = @(nm) lo.getElement(nm).Values;
        results(mode+1).mode = mode;
        results(mode+1).desc = descriptions{mode+1};
        results(mode+1).stateT = getv('state_1').Time;
        results(mode+1).state = getv('state_1').Data;
        results(mode+1).authT = getv('AUTH_RESULT_1').Time;
        results(mode+1).auth = getv('AUTH_RESULT_1').Data;
        results(mode+1).replayT = getv('replay_detected_1').Time;
        results(mode+1).replay = getv('replay_detected_1').Data;
        results(mode+1).injT = getv('injection_detected_1').Time;
        results(mode+1).inj = getv('injection_detected_1').Data;
        results(mode+1).socT = getv('gated_soc_1').Time;
        results(mode+1).soc = getv('gated_soc_1').Data;
        fprintf('attack_mode=%d done\n', mode);
    end

    set_param(atkBlk, 'Value', '0');

    f = figure('Position',[100 100 1400 900], 'Color','w');
    for m = 1:6
        r = results(m);
        subplot(3,2,m);
        yyaxis left
        plot(r.stateT, r.state, 'b-', 'LineWidth', 1.8);
        ylim([-0.5 6]); ylabel('State');
        yyaxis right
        plot(r.replayT, r.replay, 'r-', 'LineWidth', 1.5); hold on;
        plot(r.injT, r.inj, 'm-', 'LineWidth', 1.5);
        plot(r.socT, r.soc, 'g-', 'LineWidth', 1.5);
        ylim([-1 90]);
        grid on;
        title(sprintf('attack_mode=%d  (%s)', r.mode, r.desc));
        xlabel('Time (s)'); ylabel('Flags / SOC');
        if m == 3
            legend({'state','replay','injection','soc'}, 'Location','south');
        end
    end
    sgtitle('BattLock Simulink Verification - Battlock_System2');
    saveas(f, 'verification_plot.png');
    close(f);

    fid = fopen('verification_report.csv', 'w');
    fprintf(fid, 'attack_mode,description,final_state,final_soc,max_replay,max_injection\n');
    for m = 1:6
        r = results(m);
        fprintf(fid, '%d,%s,%d,%.1f,%d,%d\n', ...
            r.mode, r.desc, r.state(end), r.soc(end), max(r.replay), max(r.inj));
    end
    fclose(fid);

    fprintf('\nDONE. Wrote verification_plot.png and verification_report.csv\n');
end
