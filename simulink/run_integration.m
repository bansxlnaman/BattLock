function run_integration()

    repo = fileparts(fileparts(mfilename('fullpath')));
    simdir = fullfile(repo, 'simulink');

    fprintf('\n[1/4] Exporting CAN frames from Simulink (modes 0-5)...\n');
    export_frames(simdir);

    fprintf('\n[2/4] Generating attack modes 6-11 from Python attack classes...\n');
    cmd = sprintf('py -3.11 "%s"', fullfile(simdir, 'generate_extra_modes.py'));
    [status, output] = system(cmd);
    fprintf('%s\n', output);
    if status ~= 0
        error('Python extra-mode generation failed (exit %d)', status);
    end

    fprintf('\n[3/4] Verifying all 12 modes with real BattLock Python code...\n');
    cmd = sprintf('py -3.11 "%s"', fullfile(simdir, 'verify_all_modes.py'));
    [status, output] = system(cmd);
    fprintf('%s\n', output);
    if status ~= 0
        error('Python verification failed (exit %d)', status);
    end

    fprintf('\n[4/4] Generating Python plots for all 12 modes...\n');
    cmd = sprintf('py -3.11 "%s"', fullfile(simdir, 'plot_all_modes.py'));
    [status, output] = system(cmd);
    fprintf('%s\n', output);
    if status ~= 0
        error('Python plotting failed (exit %d)', status);
    end

    fprintf('\nDONE.\n');
    fprintf('See:\n');
    fprintf('  %s\n', fullfile(simdir, 'frames_verified_all.csv'));
    fprintf('  %s\n', fullfile(simdir, 'verification_report_all.csv'));
    fprintf('  %s\n', fullfile(simdir, 'integration_plot_all.png'));
    fprintf('  %s\n', fullfile(simdir, 'modes_overview.png'));
    fprintf('\nTo view the MATLAB-style plot as well, run make_integration_plots.\n');
end
