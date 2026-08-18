function make_integration_plots(verified_csv, plot_dir, report_path)

    if nargin < 1
        verified_csv = 'frames_verified_all.csv';
    end
    if nargin < 2
        plot_dir = pwd;
    end
    if nargin < 3
        report_path = fullfile(plot_dir, 'integration_report_all_matlab.csv');
    end

    T = readtable(verified_csv);
    modes = unique(T.mode)';

    descriptions = containers.Map(...
        {0,1,2,3,4,5,6,7,8,9,10,11}, ...
        {'Normal','Replay','Spoof Sig','Voltage Inj','Drop Sig','Spoof + Inj', ...
         'MITM','Delay','Fuzzing','Session Hijack','Evasion','Cert Tamper'});

    nModes = numel(modes);
    cols = 4;
    rows = ceil(nModes / cols);

    % ---- Plot 1: Python verifier verdicts (one subplot per mode) ----
    plot_one_set(T, modes, descriptions, ...
        {'py_auth','py_replay','py_injection'}, ...
        'BattLock Integration - Python verifier verdicts for all 12 modes', ...
        fullfile(plot_dir, 'integration_plot_all_matlab.png'), rows, cols);

    % ---- Plot 2: Simulink model verdicts (one subplot per mode) ----
    plot_one_set(T, modes, descriptions, ...
        {'model_auth','model_replay','model_injection'}, ...
        'BattLock Integration - Simulink model verdicts for all 12 modes', ...
        fullfile(plot_dir, 'simulink_plot_all_matlab.png'), rows, cols);

    % ---- Per-mode agreement report ----
    fid = fopen(report_path, 'w');
    fprintf(fid, 'mode,description,py_auth,model_auth,py_replay,model_replay,py_injection,model_injection,agreement\n');
    for k = 1:nModes
        m = modes(k);
        g = T(T.mode == m, :);
        py_auth   = max(g.py_auth);
        mdl_auth  = max(g.model_auth);
        py_rep    = max(g.py_replay);
        mdl_rep   = max(g.model_replay);
        py_inj    = max(g.py_injection);
        mdl_inj   = max(g.model_injection);
        agree     = (py_auth==mdl_auth) && (py_rep==mdl_rep) && (py_inj==mdl_inj);
        fprintf(fid, '%d,%s,%d,%d,%d,%d,%d,%d,%s\n', ...
            m, descriptions(m), py_auth, mdl_auth, py_rep, mdl_rep, ...
            py_inj, mdl_inj, string(agree));
    end
    fclose(fid);
    fprintf('Wrote %s\n', report_path);
end

function plot_one_set(T, modes, descriptions, keys, title, out_path, rows, cols)
    f = figure('Position',[100 100 1600 900], 'Color','w');
    for k = 1:numel(modes)
        m = modes(k);
        g = T(T.mode == m, :);

        ax = subplot(rows, cols, k);
        stairs(g.time, g.(keys{1}), 'b-', 'LineWidth', 1.8); hold on;
        stairs(g.time, g.(keys{2}), 'r-', 'LineWidth', 1.5);
        stairs(g.time, g.(keys{3}), 'm-', 'LineWidth', 1.5);
        stairs(g.time, g.model_soc/85, 'g-', 'LineWidth', 1.5);
        ylim([-0.2 1.4]); grid on;
        title(sprintf('mode %d (%s)', m, descriptions(m)));
        xlabel('Time (s)');
        if k == 1
            legend({'auth','replay','injection','SOC/85'}, 'Location','south');
        end
    end
    sgtitle(title);
    saveas(f, out_path);
    close(f);
    fprintf('Wrote %s\n', out_path);
end