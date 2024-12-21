package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.propertyeditors.CustomDateEditor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.*;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.CatVehiculos;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service.MaintenanceService;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

@Controller
@RequestMapping("/vehiculos")
public class VehiculosController {

    @Autowired
    private MaintenanceService maintenanceService;

    @InitBinder
    public void initBinder(WebDataBinder binder) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        dateFormat.setLenient(false);
        binder.registerCustomEditor(Date.class, new CustomDateEditor(dateFormat, false));
    }

    @GetMapping("/listar")
    public String listarVehiculos(Model model) {
        List<VehiculosListarDto> vehiculos = maintenanceService.getAllVehiculos();
        model.addAttribute("vehiculos", vehiculos);
        return "vehiculos-listar";
    }

    @GetMapping("/detalle/{id}")
    public String getDetalleVehiculoById(@PathVariable Integer id, Model model) {
        CatVehiculoDetalles detalleCategoria = maintenanceService.getCategoriaDetalleByVehiculoId(id);
        model.addAttribute("categoria", detalleCategoria);
        return "vehiculos-detalles";
    }

    @GetMapping("/registrar")
    public String mostrarFormularioRegistro(Model model) {
        List<CatVehiculos> categorias = maintenanceService.getAllCategorias();
        model.addAttribute("categorias", categorias);
        model.addAttribute("vehiculo", new VehiculosRegistrarDto(null, "", "", false, null, 0, 0.0, 0, null));
        return "vehiculos-registrar";
    }

    @PostMapping("/registrar")
    public String registrarVehiculo(@ModelAttribute("vehiculo") VehiculosRegistrarDto vehiculosRegistrarDto) {
        maintenanceService.registrarVehiculo(vehiculosRegistrarDto);
        return "redirect:/vehiculos/listar";
    }

    @PostMapping("/eliminar")
    public String eliminarVehiculo(@ModelAttribute("vehiculoEliminar") VehiculosEliminarDto vehiculosEliminarDto) {
        maintenanceService.eliminarVehiculo(vehiculosEliminarDto.idVehi());
        return "redirect:/vehiculos/listar";
    }

    @GetMapping("/editar/{id}")
    public String mostrarFormularioEdicion(@PathVariable Integer id, Model model) {
        VehiculosEditarDto vehiculo = maintenanceService.getVehiculoById(id);
        List<CatVehiculos> categorias = maintenanceService.getAllCategorias();
        model.addAttribute("vehiculo", vehiculo);
        model.addAttribute("categorias", categorias);
        return "vehiculos-editar";
    }

    @PostMapping("/editar")
    public String actualizarVehiculo(@ModelAttribute("vehiculo") VehiculosEditarDto vehiculosEditarDto) {
        maintenanceService.actualizarVehiculo(vehiculosEditarDto);
        return "redirect:/vehiculos/listar";
    }


    // para principal
    @GetMapping("/cartilla")
    public String listarVehiculos2(Model model) {
        List<VehiculosListarDto> vehiculos = maintenanceService.getAllVehiculos();
        model.addAttribute("vehiculos", vehiculos);
        return "cartilla-listado";
    }
}
