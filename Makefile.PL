use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'Maypole::Plugin::Authentication::Abstract',
    AUTHOR       => 'Sebastian Riedel (sri@oook.de)',
    PREREQ_PM    => { Maypole => '2.0', URI => 0 },
    VERSION_FROM => 'Abstract.pm'
);
