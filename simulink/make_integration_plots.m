function make_integration_plots(verified_csv, plot_path, report_path)
%MAKE_INTEGRATION_PLOTS  Plot Python verdicts on the Simulink frames and
%   write a summary report comparing Python vs Simulink decisions.
%
%   Input:  verified_csv  = frames_verified.csv from verify_frames.py
%   Output: plot_path     = integration_plot.png
%           report_path   = integration_report.csv

    T = readtable(verified_csv);
    modes = unique(T.mode)';

    descriptions = containers.Map(...
        {0,1,2,3,4,5}, ...
        {'Normal','Replay','Spoof Sig','Voltage Inj','Drop Sig','Drop Sig'});

    f = figure('Position',[100 100 1400 900], 'Color','w');
    for k = 1:numel(modes)
        m = modes(k);
        g = T(T.mode == m, :);
        subplot(3,2,k);
        stairs(g.time, g.py_auth, 'b-', 'LineWidth', 1.8); hold on;
        stairs(g.time, g.py_replay, 'r-', 'LineWidth', 1.5);
        stairs(g.time, g.py_injection, 'm-', 'LineWidth', 1.5);
        stairs(g.time, g.model_soc/85, 'g-', 'LineWidth', 1.5);
        ylim([-0.2 1.4]);
        grid on;
        title(sprintf('mode %d (%s)  -  Python verdict', m, descriptions(m)));
        xlabel('Time (s)'); ylabel('0/1 flag (SOC/85)');
        legend({'auth','replay','injection','SOC/85'}, 'Location','south');
    end
    sgtitle('BattLock Integration - Python verifies Simulink CAN frames');
    saveas(f, plot_path);
    close(f);

    % ---- Report ----
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
