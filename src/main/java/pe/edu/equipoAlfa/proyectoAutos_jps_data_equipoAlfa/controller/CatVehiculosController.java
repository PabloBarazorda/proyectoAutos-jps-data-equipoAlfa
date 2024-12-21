package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.*;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service.MaintenanceCatVehiService;

import java.util.List;

@Controller
@RequestMapping("/catvehiculos")
public class CatVehiculosController {

    @Autowired
    private MaintenanceCatVehiService maintenanceCatVehiService;

    @GetMapping("/catlistar")
    public String listarCatVehiculos(Model model) {
        List<CatVehiculosListarDto> catvehiculos = maintenanceCatVehiService.getAllCatVehiculos();
        model.addAttribute("catvehiculos", catvehiculos);
        return "catvehiculos-catlistar";
    }

    @GetMapping("/cateditar/{id}")
    public String editar(@PathVariable Integer id, Model model){
        CatVehiculosEditarDto catVehiculosEditarDto = maintenanceCatVehiService.getCatVehiculosEditarDto(id);
        model.addAttribute("catvehiculo", catVehiculosEditarDto);
        return "catvehiculos-cateditar";
    }

    @PostMapping("/cateditar/{id}")
    public String editar(@PathVariable Integer id ,@ModelAttribute CatVehiculosEditarDto catVehiculosEditarDto, Model model) {
        maintenanceCatVehiService.actualizarCatVehi(id, catVehiculosEditarDto);
        return "redirect:/catvehiculos/catlistar";
    }

    /*@GetMapping("/catregistrar")
    public String mostrarCatVehiculos(Model model) {
        model.addAttribute("catvehiculos", new CatVehiculosRegistrarDto(
                null,
                "",
                false,
                "",
                ""
        ));
        return "catvehiculos-catregistrar";
    }*/
    @GetMapping("/catregistrar")
    public String registrar(Model model) {
        model.addAttribute("catVehiculos", new CatVehiculosRegistrarDto(
                null,
                "",
                false,
                "",
                ""
        ));
        return "catvehiculos-catregistrar";
    }

    @PostMapping("/catregistrar")
    public String registrarCatVehiculos(@ModelAttribute("catvehiculos") CatVehiculosRegistrarDto registarCatVehi) {
        maintenanceCatVehiService.registarCatVehi(registarCatVehi);
        return "redirect:/catvehiculos/catlistar";
    }

    @PostMapping("/cateliminar/{id}")
    public String eliminar(@PathVariable Integer id, RedirectAttributes redirectAttributes) {

        try {
            maintenanceCatVehiService.eliminarCatVehi(id);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return "redirect:/catvehiculos/catlistar";
    }

    @GetMapping("/catdetalles/{id}")
    public String detalleCatVehiculo(@PathVariable("id") Integer id, Model model) {
        CatVehiculosDetallesDto detallecatvheiculo = maintenanceCatVehiService.getCatVehiculoDetalleById(id);
        model.addAttribute("catvehiculos", detallecatvheiculo);
        return "catvehiculos-catdetalles";
    }

}
