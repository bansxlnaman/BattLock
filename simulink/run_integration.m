function run_integration()

    repo = fileparts(fileparts(mfilename('fullpath')));
    simdir = fullfile(repo, 'simulink');

    fprintf('\n[1/3] Exporting CAN frames from Simulink...\n');
    export_frames(simdir);

    fprintf('\n[2/3] Verifying frames with real BattLock Python code...\n');
    cmd = sprintf('py -3.11 "%s" "%s" "%s"', ...
        fullfile(repo, 'integration', 'verify_frames.py'), ...
        fullfile(simdir, 'frames.csv'), ...
        fullfile(simdir, 'frames_verified.csv'));
    [status, output] = system(cmd);
    fprintf('%s\n', output);
    if status ~= 0
        error('Python verification failed (exit %d)', status);
    end

    fprintf('\n[3/3] Generating integration plot and report...\n');
    make_integration_plots(fullfile(simdir, 'frames_verified.csv'), ...
        fullfile(simdir, 'integration_plot.png'), ...
        fullfile(simdir, 'integration_report.csv'));
    fprintf('DONE. See simulink/integration_plot.png and simulink/integration_report.csv\n');
end
