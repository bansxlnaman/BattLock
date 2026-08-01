function make_integration_plots(verified_csv, plot_path, report_path)

    T = readtable(verified_csv);
    modes = unique(T.mode)';

    descriptions = containers.Map(...
        {0,1,2,3,4,5}, ...
        {'Normal','Replay','Spoof Sig','Voltage Inj','Drop Sig','Spoof + Inj'});

    f = figure('Position',[100 100 1500 850], 'Color','w');
    rows = 2;
    for k = 1:numel(modes)
        m = modes(k);
        g = T(T.mode == m, :);

        % top row: Python verifier verdicts
        subplot(rows, numel(modes), k);
        stairs(g.time, g.py_auth, 'b-', 'LineWidth', 1.8); hold on;
        stairs(g.time, g.py_replay, 'r-', 'LineWidth', 1.5);
        stairs(g.time, g.py_injection, 'm-', 'LineWidth', 1.5);
        stairs(g.time, g.model_soc/85, 'g-', 'LineWidth', 1.5);
        ylim([-0.2 1.4]); grid on;
        title(sprintf('mode %d (%s)', m, descriptions(m)));
        if k == 1
            ylabel('Python verdict');
            legend({'auth','replay','injection','SOC/85'}, 'Location','south');
        end
        xlabel('Time (s)');

        % bottom row: Simulink model verdicts
        subplot(rows, numel(modes), k + numel(modes));
        stairs(g.time, g.model_auth, 'b-', 'LineWidth', 1.8); hold on;
        stairs(g.time, g.model_replay, 'r-', 'LineWidth', 1.5);
        stairs(g.time, g.model_injection, 'm-', 'LineWidth', 1.5);
        stairs(g.time, g.model_soc/85, 'g-', 'LineWidth', 1.5);
        ylim([-0.2 1.4]); grid on;
        if k == 1
            ylabel('Simulink verdict');
        end
        xlabel('Time (s)');
    end
    sgtitle('BattLock Integration - Python and Simulink verdicts (identical = agreement)');
    saveas(f, plot_path);
    close(f);

    fid = fopen(report_path, 'w');
    fprintf(fid, 'mode,description,py_auth,model_auth,py_replay,model_replay,py_injection,model_injection,agreement\n');
    for k = 1:numel(modes)
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
